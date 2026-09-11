import hmac
import hashlib
import frontmatter
import markdown
import nh3
import os
import shutil
import secrets
import re
import time
import json
import urllib.request
import requests
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional
from PIL import Image
from urllib.parse import urlparse

from fastapi import FastAPI, Request, Depends, Form, status, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth

from .database import get_db, engine
from .models import (
    Base,
    Article,
    ForumThread,
    ForumReply,
    User,
    ThreadVote,
    ReplyVote,
    Tag,
    ArticleTag,
    ThreadTag,
    Payment,
    WikiTerm,
)
from .auth import (
    hash_password,
    verify_password,
    create_session_token,
    verify_session_token,
    SECRET_KEY,
)

# Ensure tables & folders exist
Base.metadata.create_all(bind=engine)
os.makedirs("app/static/avatars", exist_ok=True)
os.makedirs("app/static/uploads", exist_ok=True)

# Application Constants
MAX_AGE_30_DAYS = 60 * 60 * 24 * 30  # 30 Days in seconds
SOLANA_WALLET = os.getenv(
    "SOLANA_WALLET_ADDRESS", "9xQeWvG816bUx9EPjHmaT23yvVM2VYdeHzM2a6C3Vfc"
)
ALLOWED_HOSTS = {"askpc.cc", "www.askpc.cc", "localhost:8000", "127.0.0.1:8000"}

# FastAPI App Init
app = FastAPI(title="askpc.cc", docs_url=None, redoc_url=None, openapi_url=None)

# Rate Limiter
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Session Middleware for OAuth State Management
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://askpc.cc",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

# Authlib OAuth Setup
oauth = OAuth()
oauth.register(
    name="github",
    client_id=os.getenv("GITHUB_CLIENT_ID"),
    client_secret=os.getenv("GITHUB_CLIENT_SECRET"),
    access_token_url="https://github.com/login/oauth/access_token",
    authorize_url="https://github.com/login/oauth/authorize",
    api_base_url="https://api.github.com/",
    client_kwargs={"scope": "user:email"},
)


# CSRF & Security Headers Middleware
@app.middleware("http")
async def add_security_headers_and_csrf(request: Request, call_next):
    if (
        request.method in ("POST", "PUT", "DELETE")
        and request.url.path != "/webhooks/github"
    ):
        origin = request.headers.get("origin") or request.headers.get("referer")
        if not origin:
            return templates.TemplateResponse(
                request=request,
                name="index.html",
                context={"error": "CSRF Validation Failed: Missing origin header."},
                status_code=403,
            )
        parsed_host = urlparse(origin).netloc
        if parsed_host not in ALLOWED_HOSTS:
            return templates.TemplateResponse(
                request=request,
                name="index.html",
                context={
                    "error": "CSRF Validation Failed: Request origin not allowed."
                },
                status_code=403,
            )

    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:;"
    )
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


# Secure File Saver (5MB Limit + Magic Bytes + Pillow Verification)
ALLOWED_ATTACHMENTS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".webp",
    ".gif",
    ".pdf",
    ".md",
    ".txt",
    ".log",
    ".py",
    ".sh",
    ".c",
    ".cpp",
    ".rs",
    ".zig",
    ".js",
    ".ts",
    ".json",
    ".conf",
}


def save_secure_file(
    upload_file: Optional[UploadFile], folder: str = "uploads"
) -> tuple[Optional[str], Optional[str]]:
    if not upload_file or not upload_file.filename:
        return None, None

    ext = os.path.splitext(upload_file.filename)[1].lower()
    if ext not in ALLOWED_ATTACHMENTS:
        raise ValueError("Unsupported file type.")

    upload_file.file.seek(0, 2)
    file_size = upload_file.file.tell()
    upload_file.file.seek(0)
    if file_size > 5 * 1024 * 1024:
        raise ValueError("File exceeds maximum 5MB size limit.")

    header = upload_file.file.read(10)
    upload_file.file.seek(0)
    if b"MZ" in header or b"ELF" in header or b"<?php" in header:
        raise ValueError("Security Violation: Executable binary payload detected.")

    if ext in {".png", ".jpg", ".jpeg", ".webp", ".gif"}:
        try:
            img = Image.open(upload_file.file)
            img.verify()
            upload_file.file.seek(0)
        except Exception:
            raise ValueError("Corrupted or invalid image file.")

    filename = f"{secrets.token_hex(10)}{ext}"
    filepath = f"app/static/{folder}/{filename}"
    with open(filepath, "wb") as buffer:
        shutil.copyfileobj(upload_file.file, buffer)

    return f"/static/{folder}/{filename}", upload_file.filename


# Markdown Sanitizer (nh3)
ALLOWED_HTML_TAGS = {
    "p",
    "br",
    "strong",
    "em",
    "code",
    "pre",
    "blockquote",
    "ul",
    "ol",
    "li",
    "a",
    "img",
    "h1",
    "h2",
    "h3",
    "h4",
    "table",
    "thead",
    "tbody",
    "tr",
    "th",
    "td",
    "del",
    "hr",
    "details",
    "summary",
}
ALLOWED_HTML_ATTRS = {"a": {"href", "title"}, "img": {"src", "alt"}}


def render_markdown(text: str) -> str:
    if not text:
        return ""
    raw_html = markdown.markdown(
        text,
        extensions=[
            "markdown.extensions.extra",
            "markdown.extensions.fenced_code",
            "markdown.extensions.tables",
            "markdown.extensions.nl2br",
            "markdown.extensions.sane_lists",
            "pymdownx.tilde",
            "pymdownx.tasklist",
        ],
    )
    return nh3.clean(raw_html, tags=ALLOWED_HTML_TAGS, attributes=ALLOWED_HTML_ATTRS)


templates.env.filters["markdown"] = render_markdown


# Secure User Session Helper (auth_session)
def get_current_user(request: Request, db: Session) -> Optional[User]:
    token = request.cookies.get("auth_session")
    if not token:
        return None
    user_id = verify_session_token(token)
    if user_id:
        return db.query(User).filter(User.id == user_id).first()
    return None


# Email Senders via requests API
def send_verification_email(to_email: str, username: str, token: str):
    resend_api_key = os.getenv("RESEND_API_KEY")
    domain = os.getenv("DOMAIN", "askpc.cc").strip()
    verify_url = f"https://{domain}/verify-email?token={token}"

    if not resend_api_key:
        print(
            f"\n📧 [LOCAL DEV LOG] VERIFICATION LINK FOR @{username}: http://localhost:8000/verify-email?token={token}\n"
        )
        return

    try:
        response = requests.post(
            "https://api.resend.com/emails",
            headers={
                "Authorization": f"Bearer {resend_api_key}",
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            },
            json={
                "from": f"askpc.cc <noreply@{domain}>",
                "to": [to_email],
                "subject": "Verify your email address on askpc.cc",
                "html": f"""
                    <div style="font-family: sans-serif; max-width: 500px; margin: 0 auto; padding: 20px; border: 1px solid #e5e5e5; border-radius: 4px;">
                        <h2>Welcome to askpc.cc, @{username}!</h2>
                        <p>Please confirm your email address by clicking the link below:</p>
                        <p><a href="{verify_url}" style="display: inline-block; padding: 10px 20px; background: #111; color: #fff; text-decoration: none; border-radius: 4px;">Verify Email Address</a></p>
                    </div>
                """,
            },
            timeout=15,
        )
        if response.status_code in [200, 201]:
            print(f"✅ Real verification email sent to {to_email}")
        else:
            print(f"❌ Resend API Error {response.status_code}: {response.text}")
    except Exception as e:
        print(f"❌ Failed to send email via API: {e}")


def send_reset_password_email(to_email: str, username: str, token: str):
    resend_api_key = os.getenv("RESEND_API_KEY")
    domain = os.getenv("DOMAIN", "askpc.cc").strip()
    reset_url = f"https://{domain}/reset-password?token={token}"

    if not resend_api_key:
        print(
            f"\n🔑 [LOCAL DEV LOG] RESET PASSWORD LINK FOR @{username}: http://localhost:8000/reset-password?token={token}\n"
        )
        return

    try:
        response = requests.post(
            "https://api.resend.com/emails",
            headers={
                "Authorization": f"Bearer {resend_api_key}",
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            },
            json={
                "from": f"askpc.cc <noreply@{domain}>",
                "to": [to_email],
                "subject": "Password Reset Request for askpc.cc",
                "html": f"""
                    <div style="font-family: sans-serif; max-width: 500px; margin: 0 auto; padding: 20px; border: 1px solid #e5e5e5; border-radius: 4px;">
                        <h2>Password Reset Request</h2>
                        <p>Hi @{username}, click the link below to set a new password. Link is valid for 1 hour:</p>
                        <p><a href="{reset_url}" style="display: inline-block; padding: 10px 20px; background: #111; color: #fff; text-decoration: none; border-radius: 4px;">Set New Password</a></p>
                    </div>
                """,
            },
            timeout=15,
        )
        if response.status_code in [200, 201]:
            print(f"🔑 Password reset email sent to {to_email}")
        else:
            print(f"❌ Resend API Error {response.status_code}: {response.text}")
    except Exception as e:
        print(f"❌ Failed to send reset email: {e}")


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return FileResponse("app/static/style.css")


# --- MAIN NAVIGATION & SEARCH ---


@app.get("/")
@app.get("/index.html")
def home_page(request: Request, db: Session = Depends(get_db)):
    current_user = get_current_user(request, db)
    latest_articles = (
        db.query(Article).order_by(Article.updated_at.desc()).limit(3).all()
    )
    latest_threads = (
        db.query(ForumThread).order_by(ForumThread.created_at.desc()).limit(5).all()
    )
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "user": current_user,
            "articles": latest_articles,
            "threads": latest_threads,
        },
    )


@app.get("/kb")
@app.get("/kb.html")
def kb_page(
    request: Request,
    q: Optional[str] = None,
    tag: Optional[str] = None,
    db: Session = Depends(get_db),
):
    current_user = get_current_user(request, db)
    query = db.query(Article).distinct()
    if q:
        search_str = f"%{q.strip()}%"
        query = (
            query.outerjoin(ArticleTag)
            .outerjoin(Tag)
            .filter(
                (Article.title.ilike(search_str))
                | (Article.content_markdown.ilike(search_str))
                | (Article.category.ilike(search_str))
                | (Tag.name.ilike(search_str))
            )
        )
    if tag:
        query = query.join(ArticleTag).join(Tag).filter(Tag.name == tag.lower().strip())
    articles = query.all()
    return templates.TemplateResponse(
        request=request,
        name="kb.html",
        context={"user": current_user, "articles": articles, "q": q},
    )


@app.get("/kb/{slug}")
def article_detail(slug: str, request: Request, db: Session = Depends(get_db)):
    current_user = get_current_user(request, db)
    article = db.query(Article).filter(Article.slug == slug).first()
    if not article:
        return RedirectResponse(url="/kb", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse(
        request=request,
        name="article_detail.html",
        context={"user": current_user, "article": article},
    )


@app.get("/forum")
@app.get("/forum.html")
def forum_page(
    request: Request,
    q: Optional[str] = None,
    tag: Optional[str] = None,
    db: Session = Depends(get_db),
):
    current_user = get_current_user(request, db)
    query = db.query(ForumThread).distinct()
    if q:
        search_str = f"%{q.strip()}%"
        query = (
            query.outerjoin(ThreadTag)
            .outerjoin(Tag)
            .outerjoin(User, ForumThread.author_id == User.id)
            .filter(
                (ForumThread.title.ilike(search_str))
                | (ForumThread.content.ilike(search_str))
                | (Tag.name.ilike(search_str))
                | (User.username.ilike(search_str))
            )
        )
    if tag:
        query = query.join(ThreadTag).join(Tag).filter(Tag.name == tag.lower().strip())
    threads = query.order_by(ForumThread.created_at.desc()).all()
    return templates.TemplateResponse(
        request=request,
        name="forum.html",
        context={"user": current_user, "threads": threads, "q": q},
    )


@app.get("/tag/{tag_name}")
def tag_detail_page(tag_name: str, request: Request, db: Session = Depends(get_db)):
    current_user = get_current_user(request, db)
    tag = db.query(Tag).filter(Tag.name == tag_name.lower().strip()).first()
    if not tag:
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    articles = (
        db.query(Article).join(ArticleTag).filter(ArticleTag.tag_id == tag.id).all()
    )
    threads = (
        db.query(ForumThread).join(ThreadTag).filter(ThreadTag.tag_id == tag.id).all()
    )
    return templates.TemplateResponse(
        request=request,
        name="tag_detail.html",
        context={
            "user": current_user,
            "tag": tag,
            "articles": articles,
            "threads": threads,
        },
    )


@app.get("/community")
@app.get("/community.html")
def community_page(request: Request, db: Session = Depends(get_db)):
    current_user = get_current_user(request, db)
    active_sponsors_count = db.query(User).filter(User.is_sponsor == True).count()
    progress_percent = min(100, int((active_sponsors_count / 10) * 100))
    return templates.TemplateResponse(
        request=request,
        name="community.html",
        context={
            "user": current_user,
            "active_sponsors_count": active_sponsors_count,
            "progress_percent": progress_percent,
            "solana_wallet": SOLANA_WALLET,
        },
    )


# --- STRICT SOLANA USDT VERIFICATION (FAIL-CLOSED) ---

USDT_MINT = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"


@app.post("/community/sponsor/verify")
def verify_solana_payment(
    request: Request, tx_hash: str = Form(...), db: Session = Depends(get_db)
):
    current_user = get_current_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    def render_error(msg: str):
        active_sponsors = db.query(User).filter(User.is_sponsor == True).count()
        return templates.TemplateResponse(
            request=request,
            name="community.html",
            context={
                "user": current_user,
                "error": msg,
                "solana_wallet": SOLANA_WALLET,
                "active_sponsors_count": active_sponsors,
                "progress_percent": min(100, int((active_sponsors / 10) * 100)),
            },
        )

    tx_clean = tx_hash.strip()

    # 1. Base58 format check (Standard Solana Signature is 64-96 chars base58)
    if not re.match(r"^[1-9A-HJ-NP-Za-km-z]{64,96}$", tx_clean):
        return render_error(
            "Invalid Solana transaction signature format. Please check the hash."
        )

    # 2. Duplicate prevention check
    existing_pay = db.query(Payment).filter(Payment.tx_hash == tx_clean).first()
    if existing_pay:
        return render_error("This transaction signature has already been claimed.")

    if not SOLANA_WALLET or SOLANA_WALLET == "None":
        return render_error("Deposit wallet is not configured on the server.")

    # 3. Query Solana Mainnet RPC
    solana_rpc_url = "https://api.mainnet-beta.solana.com"
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getTransaction",
        "params": [
            tx_clean,
            {"encoding": "jsonParsed", "maxSupportedTransactionVersion": 0},
        ],
    }

    try:
        resp = requests.post(
            solana_rpc_url,
            json=payload,
            headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
            timeout=15,
        )
        if resp.status_code != 200:
            return render_error(
                "Could not connect to Solana network. Please try again in a moment."
            )

        data = resp.json()
    except Exception as e:
        print(f"❌ Solana RPC Network Error: {e}")
        return render_error(
            "Network timeout while querying Solana blockchain. Please try again."
        )

    result = data.get("result")
    if not result:
        return render_error(
            "Transaction not found on Solana blockchain. Please wait a minute for confirmation."
        )

    # 4. Check if transaction succeeded on-chain
    meta = result.get("meta") or {}
    if meta.get("err") is not None:
        return render_error("This transaction failed on the Solana blockchain.")

    # 5. Verify USDT balance increase for our wallet
    pre_balances = meta.get("preTokenBalances") or []
    post_balances = meta.get("postTokenBalances") or []

    # Calculate net USDT transferred to our wallet
    pre_amount = 0.0
    for b in pre_balances:
        if b.get("owner") == SOLANA_WALLET and b.get("mint") == USDT_MINT:
            pre_amount += float(b.get("uiTokenAmount", {}).get("uiAmount") or 0.0)

    post_amount = 0.0
    for b in post_balances:
        if b.get("owner") == SOLANA_WALLET and b.get("mint") == USDT_MINT:
            post_amount += float(b.get("uiTokenAmount", {}).get("uiAmount") or 0.0)

    received_usdt = post_amount - pre_amount

    # Must receive at least 2.00 USDT
    if received_usdt < 1.99:
        return render_error(
            f"Transaction verified, but received {received_usdt:.2f} USDT instead of 2.00 USDT to {SOLANA_WALLET}."
        )

    # 6. Verify Memo contains user's public_id
    raw_tx_str = json.dumps(result)
    if current_user.public_id not in raw_tx_str:
        return render_error(
            f"Transaction does not contain your required Memo ({current_user.public_id})."
        )

    # 7. SUCCESS: Record payment and grant 30 days of Sponsor status
    new_pay = Payment(
        user_id=current_user.id, tx_hash=tx_clean, amount_usdt=received_usdt
    )
    db.add(new_pay)

    current_user.is_sponsor = True
    current_user.sponsor_until = datetime.utcnow() + timedelta(days=30)
    db.commit()

    active_sponsors = db.query(User).filter(User.is_sponsor == True).count()
    return templates.TemplateResponse(
        request=request,
        name="community.html",
        context={
            "user": current_user,
            "message": "🎉 Payment verified successfully on Solana blockchain! Sponsor status is active for 30 days.",
            "solana_wallet": SOLANA_WALLET,
            "active_sponsors_count": active_sponsors,
            "progress_percent": min(100, int((active_sponsors / 10) * 100)),
        },
    )


@app.get("/rules")
@app.get("/rules.html")
def rules_page(request: Request, db: Session = Depends(get_db)):
    current_user = get_current_user(request, db)
    return templates.TemplateResponse(
        request=request, name="rules.html", context={"user": current_user}
    )


@app.get("/privacy")
@app.get("/privacy.html")
def privacy_page(request: Request, db: Session = Depends(get_db)):
    current_user = get_current_user(request, db)
    return templates.TemplateResponse(
        request=request, name="privacy.html", context={"user": current_user}
    )


# --- FORUM THREAD & REPLIES & VOTING ---


@app.get("/forum/new")
def new_thread_page(request: Request, db: Session = Depends(get_db)):
    current_user = get_current_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse(
        request=request, name="create_thread.html", context={"user": current_user}
    )


@app.post("/forum/new")
@limiter.limit("10/hour")
def create_thread(
    request: Request,
    title: str = Form(...),
    tags: str = Form(...),
    content: str = Form(...),
    attachment: Optional[UploadFile] = File(None),
    db: Session = Depends(get_db),
):
    current_user = get_current_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    if not current_user.is_email_verified:
        return templates.TemplateResponse(
            request=request,
            name="create_thread.html",
            context={
                "user": current_user,
                "error": "Email verification required before posting. Please check your inbox or settings.",
            },
        )

    try:
        attach_url, attach_name = save_secure_file(attachment, "uploads")
    except ValueError as err:
        return templates.TemplateResponse(
            request=request,
            name="create_thread.html",
            context={"user": current_user, "error": str(err)},
        )

    slug = f"{re.sub(r'[^a-z0-9]+', '-', title.lower()).strip('-')}-{int(time.time())}"
    new_thread = ForumThread(
        title=title,
        slug=slug,
        content=content,
        attachment_url=attach_url,
        attachment_name=attach_name,
        author_id=current_user.id,
    )
    db.add(new_thread)
    db.commit()

    tag_list = [t.strip().lstrip("#") for t in tags.split() if t.strip()]
    for tag_name in tag_list:
        clean_name = re.sub(r"[^a-zA-Z0-9_-]", "", tag_name.lower())
        if clean_name:
            tag_obj = db.query(Tag).filter(Tag.name == clean_name).first()
            if not tag_obj:
                tag_obj = Tag(name=clean_name)
                db.add(tag_obj)
                db.commit()
            new_thread.tags.append(tag_obj)

    db.commit()
    return RedirectResponse(url="/forum", status_code=status.HTTP_302_FOUND)


@app.get("/forum/thread/{slug}")
def thread_detail(slug: str, request: Request, db: Session = Depends(get_db)):
    current_user = get_current_user(request, db)
    thread = db.query(ForumThread).filter(ForumThread.slug == slug).first()
    if not thread:
        return RedirectResponse(url="/forum", status_code=status.HTTP_302_FOUND)
    replies = (
        db.query(ForumReply)
        .filter(ForumReply.thread_id == thread.id)
        .order_by(ForumReply.created_at.asc())
        .all()
    )
    return templates.TemplateResponse(
        request=request,
        name="thread_detail.html",
        context={"user": current_user, "thread": thread, "replies": replies},
    )


@app.post("/forum/thread/{slug}/reply")
def add_reply(
    slug: str,
    request: Request,
    content: str = Form(...),
    attachment: Optional[UploadFile] = File(None),
    db: Session = Depends(get_db),
):
    current_user = get_current_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    if not current_user.is_email_verified:
        thread = db.query(ForumThread).filter(ForumThread.slug == slug).first()
        replies = (
            db.query(ForumReply).filter(ForumReply.thread_id == thread.id).all()
            if thread
            else []
        )
        return templates.TemplateResponse(
            request=request,
            name="thread_detail.html",
            context={
                "user": current_user,
                "thread": thread,
                "replies": replies,
                "error": "Email verification required before replying.",
            },
        )

    thread = db.query(ForumThread).filter(ForumThread.slug == slug).first()
    if thread:
        try:
            attach_url, attach_name = save_secure_file(attachment, "uploads")
        except ValueError as err:
            replies = (
                db.query(ForumReply)
                .filter(ForumReply.thread_id == thread.id)
                .order_by(ForumReply.created_at.asc())
                .all()
            )
            return templates.TemplateResponse(
                request=request,
                name="thread_detail.html",
                context={
                    "user": current_user,
                    "thread": thread,
                    "replies": replies,
                    "error": str(err),
                },
            )

        reply = ForumReply(
            thread_id=thread.id,
            author_id=current_user.id,
            content=content,
            attachment_url=attach_url,
            attachment_name=attach_name,
        )
        db.add(reply)
        db.commit()
    return RedirectResponse(
        url=f"/forum/thread/{slug}", status_code=status.HTTP_302_FOUND
    )


@app.post("/forum/thread/{slug}/vote")
def vote_thread(
    slug: str,
    request: Request,
    direction: str = Form(...),
    db: Session = Depends(get_db),
):
    current_user = get_current_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    thread = db.query(ForumThread).filter(ForumThread.slug == slug).first()
    if not thread:
        return RedirectResponse(url="/forum", status_code=status.HTTP_302_FOUND)
    vote_val = 1 if direction == "up" else -1
    existing_vote = (
        db.query(ThreadVote)
        .filter(
            ThreadVote.user_id == current_user.id, ThreadVote.thread_id == thread.id
        )
        .first()
    )
    author = db.query(User).filter(User.id == thread.author_id).first()
    if existing_vote:
        if existing_vote.value == vote_val:
            thread.score -= vote_val
            if author:
                author.karma -= vote_val
            db.delete(existing_vote)
        else:
            thread.score += vote_val * 2
            if author:
                author.karma += vote_val * 2
            existing_vote.value = vote_val
    else:
        db.add(ThreadVote(user_id=current_user.id, thread_id=thread.id, value=vote_val))
        thread.score += vote_val
        if author:
            author.karma += vote_val
    db.commit()
    return RedirectResponse(
        url=f"/forum/thread/{slug}", status_code=status.HTTP_302_FOUND
    )


@app.post("/forum/reply/{reply_id}/vote")
def vote_reply(
    reply_id: int,
    request: Request,
    direction: str = Form(...),
    db: Session = Depends(get_db),
):
    current_user = get_current_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    reply = db.query(ForumReply).filter(ForumReply.id == reply_id).first()
    if not reply:
        return RedirectResponse(url="/forum", status_code=status.HTTP_302_FOUND)
    vote_val = 1 if direction == "up" else -1
    existing_vote = (
        db.query(ReplyVote)
        .filter(ReplyVote.user_id == current_user.id, ReplyVote.reply_id == reply.id)
        .first()
    )
    author = db.query(User).filter(User.id == reply.author_id).first()
    if existing_vote:
        if existing_vote.value == vote_val:
            reply.score -= vote_val
            if author:
                author.karma -= vote_val
            db.delete(existing_vote)
        else:
            reply.score += vote_val * 2
            if author:
                author.karma += vote_val * 2
            existing_vote.value = vote_val
    else:
        db.add(ReplyVote(user_id=current_user.id, reply_id=reply.id, value=vote_val))
        reply.score += vote_val
        if author:
            author.karma += vote_val
    db.commit()
    return RedirectResponse(
        url=f"/forum/thread/{reply.thread.slug}", status_code=status.HTTP_302_FOUND
    )


# --- USER PROFILE & SETTINGS ---


@app.get("/settings")
def settings_page(request: Request, db: Session = Depends(get_db)):
    current_user = get_current_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse(
        request=request, name="settings.html", context={"user": current_user}
    )


@app.post("/settings")
def update_settings(
    request: Request,
    experience_badge: str = Form(...),
    bio: str = Form(""),
    custom_color: Optional[str] = Form(None),
    avatar: Optional[UploadFile] = File(None),
    db: Session = Depends(get_db),
):
    current_user = get_current_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    if experience_badge in ["Teapot", "User", "Pro"]:
        current_user.experience_badge = experience_badge

    if bio:
        current_user.bio = bio.strip()[:1000]
    else:
        current_user.bio = None

    if avatar and avatar.filename:
        try:
            avatar_url, _ = save_secure_file(avatar, "avatars")
            if avatar_url:
                current_user.avatar_url = avatar_url
        except ValueError as err:
            return templates.TemplateResponse(
                request=request,
                name="settings.html",
                context={"user": current_user, "error": str(err)},
            )

    if (
        current_user.is_sponsor
        or current_user.system_role in ["founder", "co_founder", "admin"]
    ) and custom_color:
        current_user.custom_color = custom_color

    db.commit()
    return templates.TemplateResponse(
        request=request,
        name="settings.html",
        context={"user": current_user, "message": "Settings updated successfully!"},
    )


@app.post("/settings/security/username")
def change_username(
    request: Request, new_username: str = Form(...), db: Session = Depends(get_db)
):
    current_user = get_current_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    if (
        current_user.last_username_change
        and current_user.last_username_change > datetime.utcnow() - timedelta(days=14)
    ):
        next_date = (current_user.last_username_change + timedelta(days=14)).strftime(
            "%Y-%m-%d"
        )
        return templates.TemplateResponse(
            request=request,
            name="settings.html",
            context={
                "user": current_user,
                "error": f"Username can only be changed once every 14 days. Next available on {next_date}.",
            },
        )
    existing = (
        db.query(User)
        .filter(User.username == new_username, User.id != current_user.id)
        .first()
    )
    if existing:
        return templates.TemplateResponse(
            request=request,
            name="settings.html",
            context={"user": current_user, "error": "Username is already taken."},
        )
    current_user.username = new_username.strip()
    current_user.last_username_change = datetime.utcnow()
    db.commit()
    return templates.TemplateResponse(
        request=request,
        name="settings.html",
        context={"user": current_user, "message": "Username updated successfully!"},
    )


@app.post("/settings/security/email")
def change_email(
    request: Request, new_email: str = Form(...), db: Session = Depends(get_db)
):
    current_user = get_current_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    if (
        current_user.last_email_change
        and current_user.last_email_change > datetime.utcnow() - timedelta(days=14)
    ):
        next_date = (current_user.last_email_change + timedelta(days=14)).strftime(
            "%Y-%m-%d"
        )
        return templates.TemplateResponse(
            request=request,
            name="settings.html",
            context={
                "user": current_user,
                "error": f"Email can only be changed once every 14 days. Next available on {next_date}.",
            },
        )
    existing = (
        db.query(User)
        .filter(User.email == new_email, User.id != current_user.id)
        .first()
    )
    if existing:
        return templates.TemplateResponse(
            request=request,
            name="settings.html",
            context={"user": current_user, "error": "Email is already registered."},
        )
    token = secrets.token_urlsafe(32)
    current_user.email = new_email.strip()
    current_user.is_email_verified = False
    current_user.email_verification_token = token
    current_user.last_email_change = datetime.utcnow()
    db.commit()
    send_verification_email(new_email.strip(), current_user.username, token)
    return templates.TemplateResponse(
        request=request,
        name="settings.html",
        context={
            "user": current_user,
            "message": "Email updated! Verification link sent.",
        },
    )


@app.post("/settings/security/password")
def change_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    db: Session = Depends(get_db),
):
    current_user = get_current_user(request, db)
    if not current_user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    if not current_user.hashed_password or not verify_password(
        current_password, current_user.hashed_password
    ):
        return templates.TemplateResponse(
            request=request,
            name="settings.html",
            context={"user": current_user, "error": "Current password is incorrect."},
        )
    if (
        current_user.last_password_change
        and current_user.last_password_change > datetime.utcnow() - timedelta(days=14)
    ):
        next_date = (current_user.last_password_change + timedelta(days=14)).strftime(
            "%Y-%m-%d"
        )
        return templates.TemplateResponse(
            request=request,
            name="settings.html",
            context={
                "user": current_user,
                "error": f"Password can only be changed once every 14 days. Next available on {next_date}.",
            },
        )
    current_user.hashed_password = hash_password(new_password)
    current_user.last_password_change = datetime.utcnow()
    db.commit()
    return templates.TemplateResponse(
        request=request,
        name="settings.html",
        context={"user": current_user, "message": "Password updated successfully!"},
    )


@app.get("/verify-email")
def verify_email(token: str, request: Request, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email_verification_token == token).first()
    if not user:
        return templates.TemplateResponse(
            request=request,
            name="settings.html",
            context={"error": "Invalid or expired verification token."},
        )
    user.is_email_verified = True
    user.email_verification_token = None
    db.commit()
    return RedirectResponse(
        url="/settings?message=Email+verified+successfully!",
        status_code=status.HTTP_302_FOUND,
    )


@app.get("/forgot-password")
def forgot_password_page(request: Request):
    return templates.TemplateResponse(
        request=request, name="forgot_password.html", context={}
    )


@app.post("/forgot-password")
@limiter.limit("3/hour")
def process_forgot_password(
    request: Request, email: str = Form(...), db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.email == email.strip()).first()
    if user:
        token = secrets.token_urlsafe(32)
        user.reset_password_token = token
        user.reset_password_expiry = datetime.utcnow() + timedelta(hours=1)
        db.commit()
        send_reset_password_email(user.email, user.username, token)

    return templates.TemplateResponse(
        request=request,
        name="forgot_password.html",
        context={
            "message": "If an account with that email exists, a password reset link has been sent."
        },
    )


@app.get("/reset-password")
def reset_password_page(token: str, request: Request, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.reset_password_token == token).first()
    if (
        not user
        or not user.reset_password_expiry
        or user.reset_password_expiry < datetime.utcnow()
    ):
        return templates.TemplateResponse(
            request=request,
            name="forgot_password.html",
            context={"error": "Invalid or expired password reset link."},
        )

    return templates.TemplateResponse(
        request=request, name="reset_password.html", context={"token": token}
    )


@app.post("/reset-password")
def process_reset_password(
    request: Request,
    token: str = Form(...),
    new_password: str = Form(...),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.reset_password_token == token).first()
    if (
        not user
        or not user.reset_password_expiry
        or user.reset_password_expiry < datetime.utcnow()
    ):
        return templates.TemplateResponse(
            request=request,
            name="forgot_password.html",
            context={"error": "Invalid or expired password reset link."},
        )

    user.hashed_password = hash_password(new_password)
    user.reset_password_token = None
    user.reset_password_expiry = None
    user.last_password_change = datetime.utcnow()
    db.commit()

    return RedirectResponse(
        url="/login?message=Password+reset+successful!+Please+log+in.",
        status_code=status.HTTP_302_FOUND,
    )


@app.get("/u/{username}")
def public_profile(username: str, request: Request, db: Session = Depends(get_db)):
    current_user = get_current_user(request, db)
    profile_user = db.query(User).filter(User.username == username).first()
    if not profile_user:
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    threads = (
        db.query(ForumThread).filter(ForumThread.author_id == profile_user.id).all()
    )
    return templates.TemplateResponse(
        request=request,
        name="profile.html",
        context={
            "user": current_user,
            "profile_user": profile_user,
            "threads": threads,
        },
    )


# --- UNIFIED GITHUB OAUTH ROUTES ---


@app.get("/auth/github")
@app.get("/settings/github/link")
async def github_login(request: Request):
    redirect_uri = f"https://{os.getenv('DOMAIN', 'askpc.cc')}/auth/github/callback"
    return await oauth.github.authorize_redirect(request, redirect_uri)


@app.get("/auth/github/callback")
async def github_callback(request: Request, db: Session = Depends(get_db)):
    try:
        token = await oauth.github.authorize_access_token(request)
        resp = await oauth.github.get("user", token=token)
        profile = resp.json()

        gh_username = profile.get("login")
        avatar = profile.get("avatar_url")

        email = profile.get("email")
        if not email:
            emails_resp = await oauth.github.get("user/emails", token=token)
            emails = emails_resp.json()
            primary_email = next((e["email"] for e in emails if e.get("primary")), None)
            email = primary_email or f"{gh_username}@github.oauth"

        current_user = get_current_user(request, db)

        if current_user:
            existing = (
                db.query(User)
                .filter(User.github_username == gh_username, User.id != current_user.id)
                .first()
            )
            if existing:
                return RedirectResponse(
                    url=f"/settings?error=GitHub+account+@{gh_username}+is+already+linked+to+another+user",
                    status_code=status.HTTP_302_FOUND,
                )

            current_user.github_username = gh_username
            current_user.is_email_verified = True
            if current_user.avatar_url == "/static/default-avatar.png" and avatar:
                current_user.avatar_url = avatar

            db.commit()
            return RedirectResponse(
                url=f"/settings?message=GitHub+account+@{gh_username}+linked+successfully!",
                status_code=status.HTTP_302_FOUND,
            )

        user = (
            db.query(User)
            .filter(
                (User.email == email)
                | (User.github_username == gh_username)
                | (User.username == gh_username)
            )
            .first()
        )
        if not user:
            user = User(
                username=gh_username,
                github_username=gh_username,
                email=email,
                avatar_url=avatar,
                is_email_verified=True,
            )
            db.add(user)
            db.commit()
            db.refresh(user)
        else:
            if not user.github_username:
                user.github_username = gh_username
                db.commit()

        response = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
        session_token = create_session_token(user.id)
        response.set_cookie(
            key="auth_session",
            value=session_token,
            max_age=MAX_AGE_30_DAYS,
            httponly=True,
            samesite="lax",
            secure=True,
        )
        return response

    except Exception as e:
        print(f"❌ GitHub OAuth Callback Error: {e}")
        return RedirectResponse(
            url="/login?error=OAuth+failed", status_code=status.HTTP_302_FOUND
        )


@app.post("/settings/github/unlink")
def unlink_github(request: Request, db: Session = Depends(get_db)):
    current_user = get_current_user(request, db)
    if current_user:
        current_user.github_username = None
        db.commit()
    return RedirectResponse(
        url="/settings?message=GitHub+account+unlinked",
        status_code=status.HTTP_302_FOUND,
    )


# --- GITHUB WEBHOOK FOR AUTOMATIC DOCS SYNC ---


def verify_github_signature(
    raw_body: bytes, signature_header: str, secret: str
) -> bool:
    if not signature_header or not signature_header.startswith("sha256="):
        return False
    expected_signature = hmac.new(
        secret.encode("utf-8"), raw_body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(f"sha256={expected_signature}", signature_header)


def delete_github_md_file(file_path: str, db: Session):
    article = db.query(Article).filter(Article.file_path == file_path).first()
    if article:
        db.query(ArticleTag).filter(ArticleTag.article_id == article.id).delete()
        db.delete(article)
        db.commit()


def sync_github_md_file(md_content: str, file_path: str, db: Session):
    post = frontmatter.loads(md_content)
    raw_title = post.get("title", Path(file_path).stem)
    slug = re.sub(r"[^a-z0-9]+", "-", raw_title.lower()).strip("-")

    def replace_wikilink(match):
        target = match.group(1).strip()
        display = match.group(2).strip() if match.group(2) else target
        link_slug = re.sub(r"[^a-z0-9]+", "-", target.lower()).strip("-")
        return f"[{display}](/kb/{link_slug})"

    cleaned_content = re.sub(
        r"\[\[([^\|\]]+)(?:\|([^\]]+))?\]\]", replace_wikilink, post.content
    )

    author = db.query(User).filter(User.username == "admin").first()
    author_id = author.id if author else 1

    article = db.query(Article).filter(Article.file_path == file_path).first()
    if not article:
        article = db.query(Article).filter(Article.slug == slug).first()
    if not article:
        article = Article(
            title=raw_title, slug=slug, file_path=file_path, author_id=author_id
        )
        db.add(article)

    article.title = raw_title
    article.slug = slug
    article.file_path = file_path
    article.category = post.get("category", "General")
    article.difficulty = post.get("difficulty", "Beginner")
    article.license = post.get("license", "CC-BY-SA-4.0")
    article.content_markdown = cleaned_content
    article.updated_at = datetime.utcnow()

    raw_tags = post.get("tags", [])
    if isinstance(raw_tags, str):
        raw_tags = [t.strip() for t in raw_tags.split(",")]

    article.tags = []
    for tag_str in raw_tags:
        clean_name = re.sub(r"[^a-zA-Z0-9_-]", "", tag_str.lower().strip().lstrip("#"))
        if clean_name:
            tag_obj = db.query(Tag).filter(Tag.name == clean_name).first()
            if not tag_obj:
                tag_obj = Tag(name=clean_name)
                db.add(tag_obj)
                db.commit()
            article.tags.append(tag_obj)

    db.commit()


# --- WIKI SYNC VIA GITHUB WEBHOOK ---


def delete_github_wiki_file(file_path: str, db: Session):
    slug = re.sub(r"[^a-z0-9]+", "-", Path(file_path).stem.lower()).strip("-")
    term = db.query(WikiTerm).filter(WikiTerm.slug == slug).first()
    if term:
        db.delete(term)
        db.commit()
        print(f"🗑️ Cleaned up deleted wiki term: {slug}")


# Global Helper to convert Obsidian [[Wiki Links]] -> Markdown [Text](/prefix/slug)
def convert_obsidian_wikilinks(text: str, default_prefix: str = "kb") -> str:
    def replace_wikilink(match):
        target = match.group(1).strip()
        display = match.group(2).strip() if match.group(2) else target
        link_slug = re.sub(r"[^a-z0-9]+", "-", target.lower()).strip("-")
        return f"[{display}](/{default_prefix}/{link_slug})"

    return re.sub(r"\[\[([^\|\]]+)(?:\|([^\]]+))?\]\]", replace_wikilink, text)


def sync_github_wiki_file(md_content: str, file_path: str, db: Session):
    post = frontmatter.loads(md_content)
    stem = Path(file_path).stem
    term_title = post.get("term") or post.get("title") or stem.replace("-", " ").title()
    slug = re.sub(r"[^a-z0-9]+", "-", stem.lower()).strip("-")

    summary = post.get("summary")
    if not summary:
        lines = [
            l.strip()
            for l in post.content.split("\n")
            if l.strip() and not l.startswith("#")
        ]
        summary = lines[0][:300] if lines else f"Technical definition for {term_title}"

    cleaned_content = convert_obsidian_wikilinks(post.content, default_prefix="wiki")

    term_obj = db.query(WikiTerm).filter(WikiTerm.slug == slug).first()
    if not term_obj:
        term_obj = WikiTerm(term=term_title, slug=slug, summary=summary)
        db.add(term_obj)

    term_obj.term = term_title
    term_obj.slug = slug
    term_obj.summary = summary
    term_obj.category = post.get("category", "General")
    term_obj.content_markdown = cleaned_content
    term_obj.updated_at = datetime.utcnow()

    db.commit()
    print(f"✅ Webhook Synced Wiki Term: {term_title} (slug: {slug})")


@app.post("/webhooks/github")
async def github_webhook(request: Request, db: Session = Depends(get_db)):
    raw_body = await request.body()
    signature = request.headers.get("X-Hub-Signature-256")
    webhook_secret = os.getenv("GITHUB_WEBHOOK_SECRET")
    if not webhook_secret:
        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context={"error": "Webhook Secret Not Configured"},
            status_code=500,
        )

    if not verify_github_signature(raw_body, signature, webhook_secret):
        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context={"error": "Invalid Webhook Signature"},
            status_code=403,
        )

    payload = await request.json()

    commits = payload.get("commits", [])
    repo_full_name = payload.get("repository", {}).get("full_name")
    ref = payload.get("ref", "")
    branch = ref.replace("refs/heads/", "") if ref else "main"
    github_token = os.getenv("GITHUB_TOKEN")

    for commit in commits:
        # 1. Handle Added / Modified files
        modified_files = commit.get("added", []) + commit.get("modified", [])
        for file_path in modified_files:
            if file_path.endswith(".md"):
                raw_url = f"https://raw.githubusercontent.com/{repo_full_name}/{branch}/{file_path}"
                try:
                    headers = {"User-Agent": "FastAPI-Docs-Webhook"}
                    if github_token:
                        headers["Authorization"] = f"token {github_token}"
                    req = urllib.request.Request(raw_url, headers=headers)
                    with urllib.request.urlopen(req) as resp:
                        md_text = resp.read().decode("utf-8")

                        # ROUTE: wiki/ goes to WikiTerm, everything else to KB Article
                        if file_path.startswith("wiki/"):
                            sync_github_wiki_file(md_text, file_path, db)
                        else:
                            sync_github_md_file(md_text, file_path, db)
                except Exception as e:
                    print(f"❌ Failed to fetch {raw_url}: {e}")

        # 2. Handle Removed / Moved files
        removed_files = commit.get("removed", [])
        for file_path in removed_files:
            if file_path.endswith(".md"):
                if file_path.startswith("wiki/"):
                    delete_github_wiki_file(file_path, db)
                else:
                    delete_github_md_file(file_path, db)

    return {"status": "success", "synced": True}


# --- AUTH ROUTES ---


@app.get("/login")
@app.get("/login.html")
def login_page(request: Request):
    return templates.TemplateResponse(request=request, name="login.html", context={})


@app.get("/register")
@app.get("/register.html")
def register_page(request: Request):
    return templates.TemplateResponse(request=request, name="register.html", context={})


@app.post("/auth/register")
@limiter.limit("5/hour")
def register_user(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    existing_user = (
        db.query(User)
        .filter((User.email == email) | (User.username == username))
        .first()
    )
    if existing_user:
        return templates.TemplateResponse(
            request=request,
            name="register.html",
            context={"error": "Username or Email is already registered."},
        )

    new_user = User(
        username=username, email=email, hashed_password=hash_password(password)
    )
    db.add(new_user)
    db.commit()

    token = secrets.token_urlsafe(32)
    new_user.email_verification_token = token
    db.commit()
    send_verification_email(new_user.email, new_user.username, token)

    response = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    session_token = create_session_token(new_user.id)
    response.set_cookie(
        key="auth_session",
        value=session_token,
        max_age=MAX_AGE_30_DAYS,
        httponly=True,
        samesite="lax",
        secure=True,
    )
    return response


@app.post("/auth/login")
@limiter.limit("5/minute")
def login_user(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.email == email).first()
    if (
        not user
        or not user.hashed_password
        or not verify_password(password, user.hashed_password)
    ):
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={"error": "Invalid email or password."},
        )

    response = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    token = create_session_token(user.id)
    response.set_cookie(
        key="auth_session",
        value=token,
        max_age=MAX_AGE_30_DAYS,
        httponly=True,
        samesite="lax",
        secure=True,
    )
    return response


@app.get("/auth/logout")
def logout_user():
    response = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    response.delete_cookie(key="auth_session")
    return response


# --- WIKI & GLOSSARY ROUTES ---


@app.get("/wiki")
@app.get("/wiki.html")
def wiki_index(
    request: Request, q: Optional[str] = None, db: Session = Depends(get_db)
):
    current_user = get_current_user(request, db)
    query = db.query(WikiTerm)

    if q:
        search_str = f"%{q.strip()}%"
        query = query.filter(
            (WikiTerm.term.ilike(search_str))
            | (WikiTerm.summary.ilike(search_str))
            | (WikiTerm.category.ilike(search_str))
        )

    terms = query.order_by(WikiTerm.term.asc()).all()

    # Group terms alphabetically A-Z
    terms_by_letter = {}
    for t in terms:
        first_char = t.term[0].upper() if t.term else "#"
        if not first_char.isalpha():
            first_char = "#"
        terms_by_letter.setdefault(first_char, []).append(t)

    # Sort dictionary keys alphabetically
    sorted_grouped_terms = dict(sorted(terms_by_letter.items()))

    return templates.TemplateResponse(
        request=request,
        name="wiki.html",
        context={"user": current_user, "terms_by_letter": sorted_grouped_terms, "q": q},
    )


@app.get("/wiki/{slug}")
def wiki_detail(slug: str, request: Request, db: Session = Depends(get_db)):
    current_user = get_current_user(request, db)
    term = db.query(WikiTerm).filter(WikiTerm.slug == slug.lower().strip()).first()
    if not term:
        return RedirectResponse(url="/wiki", status_code=status.HTTP_302_FOUND)

    return templates.TemplateResponse(
        request=request,
        name="wiki_detail.html",
        context={"user": current_user, "term": term},
    )


# Fast JSON API for Hover Preview Tooltips
@app.get("/api/wiki/{slug}/summary")
def wiki_summary_api(slug: str, db: Session = Depends(get_db)):
    term = db.query(WikiTerm).filter(WikiTerm.slug == slug.lower().strip()).first()
    if not term:
        return {"error": "Term not found"}, 404
    return {
        "term": term.term,
        "slug": term.slug,
        "summary": term.summary,
        "category": term.category,
    }
