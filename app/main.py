import markdown
import nh3
import os
import shutil
import secrets
import re
import time
from datetime import datetime, timedelta
from urllib.parse import urlparse
from typing import Optional
from PIL import Image
import urllib.request
import json

from fastapi import FastAPI, Request, Depends, Form, status, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from .database import get_db, engine
from .models import Base, Article, ForumThread, ForumReply, User, ThreadVote, ReplyVote, Tag, ArticleTag, ThreadTag
from .auth import hash_password, verify_password, create_session_token, verify_session_token

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

Base.metadata.create_all(bind=engine)
os.makedirs("app/static/avatars", exist_ok=True)
os.makedirs("app/static/uploads", exist_ok=True)

app = FastAPI(title="askpc.cc", docs_url=None, redoc_url=None, openapi_url=None)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://askpc.cc", "http://localhost:8000", "http://127.0.0.1:8000"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ALLOWED EXACT DOMAIN HOSTS FOR CSRF
ALLOWED_HOSTS = {"askpc.cc", "www.askpc.cc", "localhost:8000", "127.0.0.1:8000"}

@app.middleware("http")
async def add_security_headers_and_csrf(request: Request, call_next):
    # 1. FAIL-CLOSED CSRF PROTECTION FOR POST/PUT/DELETE
    if request.method in ("POST", "PUT", "DELETE") and request.url.path != "/webhooks/github":
        origin = request.headers.get("origin") or request.headers.get("referer")

        # Reject if origin/referer header is missing entirely (Fail-Closed)
        if not origin:
            return templates.TemplateResponse(
                request=request, 
                name="index.html", 
                context={"error": "CSRF Validation Failed: Missing origin header."}, 
                status_code=403
            )

        # Parse exact host:port (prevents substring spoofing like askpc.cc.evil.com)
        parsed_host = urlparse(origin).netloc
        if parsed_host not in ALLOWED_HOSTS:
            return templates.TemplateResponse(
                request=request, 
                name="index.html", 
                context={"error": "CSRF Validation Failed: Request origin not allowed."}, 
                status_code=403
            )

    # 2. SECURITY HEADERS
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:;"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response

# 1. SECURE FILE SAVER WITH PILLOW VERIFICATION & MAGIC BYTES
ALLOWED_ATTACHMENTS = {
    ".png", ".jpg", ".jpeg", ".webp", ".gif",
    ".pdf", ".md", ".txt", ".log",
    ".py", ".sh", ".c", ".cpp", ".rs", ".zig", ".js", ".ts", ".json", ".conf"
}

def save_secure_file(upload_file: Optional[UploadFile], folder: str = "uploads") -> tuple[Optional[str], Optional[str]]:
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

    # Pillow Image Verification
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

# 2. XSS SAFE MARKDOWN PARSER WITH NH3 SANITIZATION
ALLOWED_HTML_TAGS = {
    "p","br","strong","em","code","pre","blockquote","ul","ol","li",
    "a","img","h1","h2","h3","h4","table","thead","tbody","tr","th","td","del","hr","details","summary"
}
ALLOWED_HTML_ATTRS = {
    "a": {"href", "title"}, 
    "img": {"src", "alt"}
}

def render_markdown(text: str) -> str:
    if not text: return ""
    raw_html = markdown.markdown(
        text, 
        extensions=[
            'markdown.extensions.extra', 
            'markdown.extensions.fenced_code', 
            'markdown.extensions.tables', 
            'markdown.extensions.nl2br', 
            'markdown.extensions.sane_lists', 
            'pymdownx.tilde', 
            'pymdownx.tasklist'
        ]
    )
    # Sanitize rendered HTML against Stored XSS attacks
    return nh3.clean(raw_html, tags=ALLOWED_HTML_TAGS, attributes=ALLOWED_HTML_ATTRS)

templates.env.filters["markdown"] = render_markdown

def get_current_user(request: Request, db: Session) -> Optional[User]:
    token = request.cookies.get("session")
    if not token: return None
    user_id = verify_session_token(token)
    if user_id:
        return db.query(User).filter(User.id == user_id).first()
    return None

@app.get('/favicon.ico', include_in_schema=False)
async def favicon():
    return FileResponse('app/static/style.css')

# --- MAIN NAVIGATION & SEARCH ---

@app.get("/")
@app.get("/index.html")
def home_page(request: Request, db: Session = Depends(get_db)):
    current_user = get_current_user(request, db)
    latest_articles = db.query(Article).order_by(Article.updated_at.desc()).limit(3).all()
    latest_threads = db.query(ForumThread).order_by(ForumThread.created_at.desc()).limit(5).all()
    return templates.TemplateResponse(request=request, name="index.html", context={"user": current_user, "articles": latest_articles, "threads": latest_threads})

@app.get("/kb")
@app.get("/kb.html")
def kb_page(request: Request, q: Optional[str] = None, tag: Optional[str] = None, db: Session = Depends(get_db)):
    current_user = get_current_user(request, db)
    query = db.query(Article).distinct()
    if q:
        search_str = f"%{q.strip()}%"
        query = query.outerjoin(ArticleTag).outerjoin(Tag).filter((Article.title.ilike(search_str)) | (Article.content_markdown.ilike(search_str)) | (Article.category.ilike(search_str)) | (Tag.name.ilike(search_str)))
    if tag:
        query = query.join(ArticleTag).join(Tag).filter(Tag.name == tag.lower().strip())
    articles = query.all()
    return templates.TemplateResponse(request=request, name="kb.html", context={"user": current_user, "articles": articles, "q": q})

@app.get("/kb/{slug}")
def article_detail(slug: str, request: Request, db: Session = Depends(get_db)):
    current_user = get_current_user(request, db)
    article = db.query(Article).filter(Article.slug == slug).first()
    if not article: return RedirectResponse(url="/kb", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse(request=request, name="article_detail.html", context={"user": current_user, "article": article})

@app.get("/forum")
@app.get("/forum.html")
def forum_page(request: Request, q: Optional[str] = None, tag: Optional[str] = None, db: Session = Depends(get_db)):
    current_user = get_current_user(request, db)
    query = db.query(ForumThread).distinct()
    if q:
        search_str = f"%{q.strip()}%"
        query = query.outerjoin(ThreadTag).outerjoin(Tag).outerjoin(User, ForumThread.author_id == User.id).filter((ForumThread.title.ilike(search_str)) | (ForumThread.content.ilike(search_str)) | (Tag.name.ilike(search_str)) | (User.username.ilike(search_str)))
    if tag:
        query = query.join(ThreadTag).join(Tag).filter(Tag.name == tag.lower().strip())
    threads = query.order_by(ForumThread.created_at.desc()).all()
    return templates.TemplateResponse(request=request, name="forum.html", context={"user": current_user, "threads": threads, "q": q})

@app.get("/tag/{tag_name}")
def tag_detail_page(tag_name: str, request: Request, db: Session = Depends(get_db)):
    current_user = get_current_user(request, db)
    tag = db.query(Tag).filter(Tag.name == tag_name.lower().strip()).first()
    if not tag: return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    articles = db.query(Article).join(ArticleTag).filter(ArticleTag.tag_id == tag.id).all()
    threads = db.query(ForumThread).join(ThreadTag).filter(ThreadTag.tag_id == tag.id).all()
    return templates.TemplateResponse(request=request, name="tag_detail.html", context={"user": current_user, "tag": tag, "articles": articles, "threads": threads})

@app.get("/community")
@app.get("/community.html")
def community_page(request: Request, db: Session = Depends(get_db)):
    current_user = get_current_user(request, db)
    return templates.TemplateResponse(request=request, name="community.html", context={"user": current_user})

@app.get("/rules")
@app.get("/rules.html")
def rules_page(request: Request, db: Session = Depends(get_db)):
    current_user = get_current_user(request, db)
    return templates.TemplateResponse(request=request, name="rules.html", context={"user": current_user})

@app.get("/privacy")
@app.get("/privacy.html")
def privacy_page(request: Request, db: Session = Depends(get_db)):
    current_user = get_current_user(request, db)
    return templates.TemplateResponse(request=request, name="privacy.html", context={"user": current_user})

# --- FORUM THREAD & REPLIES & VOTING ---

@app.get("/forum/new")
def new_thread_page(request: Request, db: Session = Depends(get_db)):
    current_user = get_current_user(request, db)
    if not current_user: return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse(request=request, name="create_thread.html", context={"user": current_user})

@app.post("/forum/new")
@limiter.limit("10/hour")
def create_thread(request: Request, title: str = Form(...), tags: str = Form(...), content: str = Form(...), attachment: Optional[UploadFile] = File(None), db: Session = Depends(get_db)):
    current_user = get_current_user(request, db)
    if not current_user: return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    try:
        attach_url, attach_name = save_secure_file(attachment, "uploads")
    except ValueError as err:
        return templates.TemplateResponse(request=request, name="create_thread.html", context={"user": current_user, "error": str(err)})

    slug = f"{re.sub(r'[^a-z0-9]+', '-', title.lower()).strip('-')}-{int(time.time())}"
    new_thread = ForumThread(title=title, slug=slug, content=content, attachment_url=attach_url, attachment_name=attach_name, author_id=current_user.id)
    db.add(new_thread)
    db.commit()

    tag_list = [t.strip().lstrip('#') for t in tags.split() if t.strip()]
    for tag_name in tag_list:
        clean_name = re.sub(r'[^a-zA-Z0-9_-]', '', tag_name.lower())
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
    if not thread: return RedirectResponse(url="/forum", status_code=status.HTTP_302_FOUND)
    replies = db.query(ForumReply).filter(ForumReply.thread_id == thread.id).order_by(ForumReply.created_at.asc()).all()
    return templates.TemplateResponse(request=request, name="thread_detail.html", context={"user": current_user, "thread": thread, "replies": replies})

@app.post("/forum/thread/{slug}/reply")
def add_reply(slug: str, request: Request, content: str = Form(...), attachment: Optional[UploadFile] = File(None), db: Session = Depends(get_db)):
    current_user = get_current_user(request, db)
    if not current_user: return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    thread = db.query(ForumThread).filter(ForumThread.slug == slug).first()
    if thread:
        try:
            attach_url, attach_name = save_secure_file(attachment, "uploads")
        except ValueError as err:
            replies = db.query(ForumReply).filter(ForumReply.thread_id == thread.id).order_by(ForumReply.created_at.asc()).all()
            return templates.TemplateResponse(request=request, name="thread_detail.html", context={"user": current_user, "thread": thread, "replies": replies, "error": str(err)})

        reply = ForumReply(thread_id=thread.id, author_id=current_user.id, content=content, attachment_url=attach_url, attachment_name=attach_name)
        db.add(reply)
        db.commit()
    return RedirectResponse(url=f"/forum/thread/{slug}", status_code=status.HTTP_302_FOUND)

@app.post("/forum/thread/{slug}/vote")
def vote_thread(slug: str, request: Request, direction: str = Form(...), db: Session = Depends(get_db)):
    current_user = get_current_user(request, db)
    if not current_user: return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    thread = db.query(ForumThread).filter(ForumThread.slug == slug).first()
    if not thread: return RedirectResponse(url="/forum", status_code=status.HTTP_302_FOUND)
    vote_val = 1 if direction == "up" else -1
    existing_vote = db.query(ThreadVote).filter(ThreadVote.user_id == current_user.id, ThreadVote.thread_id == thread.id).first()
    author = db.query(User).filter(User.id == thread.author_id).first()
    if existing_vote:
        if existing_vote.value == vote_val:
            thread.score -= vote_val
            if author: author.karma -= vote_val
            db.delete(existing_vote)
        else:
            thread.score += (vote_val * 2)
            if author: author.karma += (vote_val * 2)
            existing_vote.value = vote_val
    else:
        db.add(ThreadVote(user_id=current_user.id, thread_id=thread.id, value=vote_val))
        thread.score += vote_val
        if author: author.karma += vote_val
    db.commit()
    return RedirectResponse(url=f"/forum/thread/{slug}", status_code=status.HTTP_302_FOUND)

@app.post("/forum/reply/{reply_id}/vote")
def vote_reply(reply_id: int, request: Request, direction: str = Form(...), db: Session = Depends(get_db)):
    current_user = get_current_user(request, db)
    if not current_user: return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    reply = db.query(ForumReply).filter(ForumReply.id == reply_id).first()
    if not reply: return RedirectResponse(url="/forum", status_code=status.HTTP_302_FOUND)
    vote_val = 1 if direction == "up" else -1
    existing_vote = db.query(ReplyVote).filter(ReplyVote.user_id == current_user.id, ReplyVote.reply_id == reply.id).first()
    author = db.query(User).filter(User.id == reply.author_id).first()
    if existing_vote:
        if existing_vote.value == vote_val:
            reply.score -= vote_val
            if author: author.karma -= vote_val
            db.delete(existing_vote)
        else:
            reply.score += (vote_val * 2)
            if author: author.karma += (vote_val * 2)
            existing_vote.value = vote_val
    else:
        db.add(ReplyVote(user_id=current_user.id, reply_id=reply.id, value=vote_val))
        reply.score += vote_val
        if author: author.karma += vote_val
    db.commit()
    return RedirectResponse(url=f"/forum/thread/{reply.thread.slug}", status_code=status.HTTP_302_FOUND)

# --- USER PROFILE & SETTINGS ---

@app.get("/settings")
def settings_page(request: Request, db: Session = Depends(get_db)):
    current_user = get_current_user(request, db)
    if not current_user: return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse(request=request, name="settings.html", context={"user": current_user})

@app.post("/settings")
def update_settings(
    request: Request,
    experience_badge: str = Form(...),
    bio: str = Form(""),
    custom_color: Optional[str] = Form(None),
    avatar: Optional[UploadFile] = File(None),
    db: Session = Depends(get_db)
):
    current_user = get_current_user(request, db)
    if not current_user: return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

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
            return templates.TemplateResponse(request=request, name="settings.html", context={"user": current_user, "error": str(err)})

    if (current_user.is_sponsor or current_user.system_role in ["founder", "co_founder", "admin"]) and custom_color:
        current_user.custom_color = custom_color

    db.commit()
    return templates.TemplateResponse(request=request, name="settings.html", context={"user": current_user, "message": "Settings updated successfully!"})

@app.post("/settings/security/username")
def change_username(request: Request, new_username: str = Form(...), db: Session = Depends(get_db)):
    current_user = get_current_user(request, db)
    if not current_user: return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    if current_user.last_username_change and current_user.last_username_change > datetime.utcnow() - timedelta(days=14):
        next_date = (current_user.last_username_change + timedelta(days=14)).strftime('%Y-%m-%d')
        return templates.TemplateResponse(request=request, name="settings.html", context={"user": current_user, "error": f"Username can only be changed once every 14 days. Next available on {next_date}."})
    existing = db.query(User).filter(User.username == new_username, User.id != current_user.id).first()
    if existing:
        return templates.TemplateResponse(request=request, name="settings.html", context={"user": current_user, "error": "Username is already taken."})
    current_user.username = new_username.strip()
    current_user.last_username_change = datetime.utcnow()
    db.commit()
    return templates.TemplateResponse(request=request, name="settings.html", context={"user": current_user, "message": "Username updated successfully!"})

@app.post("/settings/security/email")
def change_email(request: Request, new_email: str = Form(...), db: Session = Depends(get_db)):
    current_user = get_current_user(request, db)
    if not current_user: return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    if current_user.last_email_change and current_user.last_email_change > datetime.utcnow() - timedelta(days=14):
        next_date = (current_user.last_email_change + timedelta(days=14)).strftime('%Y-%m-%d')
        return templates.TemplateResponse(request=request, name="settings.html", context={"user": current_user, "error": f"Email can only be changed once every 14 days. Next available on {next_date}."})
    existing = db.query(User).filter(User.email == new_email, User.id != current_user.id).first()
    if existing:
        return templates.TemplateResponse(request=request, name="settings.html", context={"user": current_user, "error": "Email is already registered."})
    token = secrets.token_urlsafe(32)
    current_user.email = new_email.strip()
    current_user.is_email_verified = False
    current_user.email_verification_token = token
    current_user.last_email_change = datetime.utcnow()
    db.commit()
    send_verification_email(new_email.strip(), current_user.username, token)
    return templates.TemplateResponse(request=request, name="settings.html", context={"user": current_user, "message": "Email updated! Verification link sent (Check terminal logs)."})

@app.post("/settings/security/password")
def change_password(request: Request, current_password: str = Form(...), new_password: str = Form(...), db: Session = Depends(get_db)):
    current_user = get_current_user(request, db)
    if not current_user: return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    if not current_user.hashed_password or not verify_password(current_password, current_user.hashed_password):
        return templates.TemplateResponse(request=request, name="settings.html", context={"user": current_user, "error": "Current password is incorrect."})
    if current_user.last_password_change and current_user.last_password_change > datetime.utcnow() - timedelta(days=14):
        next_date = (current_user.last_password_change + timedelta(days=14)).strftime('%Y-%m-%d')
        return templates.TemplateResponse(request=request, name="settings.html", context={"user": current_user, "error": f"Password can only be changed once every 14 days. Next available on {next_date}."})
    current_user.hashed_password = hash_password(new_password)
    current_user.last_password_change = datetime.utcnow()
    db.commit()
    return templates.TemplateResponse(request=request, name="settings.html", context={"user": current_user, "message": "Password updated successfully!"})

@app.get("/verify-email")
def verify_email(token: str, request: Request, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email_verification_token == token).first()
    if not user:
        return templates.TemplateResponse(request=request, name="settings.html", context={"error": "Invalid or expired verification token."})
    user.is_email_verified = True
    user.email_verification_token = None
    db.commit()
    return RedirectResponse(url="/settings?message=Email+verified+successfully!", status_code=status.HTTP_302_FOUND)

@app.post("/settings/toggle-sponsor")
def toggle_sponsor(request: Request, db: Session = Depends(get_db)):
    current_user = get_current_user(request, db)
    if current_user:
        current_user.is_sponsor = not current_user.is_sponsor
        if current_user.id == 1:
            current_user.system_role = "founder"
        db.commit()
    return RedirectResponse(url="/settings", status_code=status.HTTP_302_FOUND)

@app.get("/u/{username}")
def public_profile(username: str, request: Request, db: Session = Depends(get_db)):
    current_user = get_current_user(request, db)
    profile_user = db.query(User).filter(User.username == username).first()
    if not profile_user: return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    threads = db.query(ForumThread).filter(ForumThread.author_id == profile_user.id).all()
    return templates.TemplateResponse(request=request, name="profile.html", context={"user": current_user, "profile_user": profile_user, "threads": threads})

# --- GITHUB WEBHOOK FOR AUTOMATIC DOCS SYNC ---

def verify_github_signature(raw_body: bytes, signature_header: str, secret: str) -> bool:
    if not signature_header or not signature_header.startswith("sha256="): return False
    expected_signature = hmac.new(secret.encode('utf-8'), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(f"sha256={expected_signature}", signature_header)

def sync_github_md_file(md_content: str, file_path: str, db: Session):
    post = frontmatter.loads(md_content)
    raw_title = post.get("title", Path(file_path).stem)
    slug = re.sub(r'[^a-z0-9]+', '-', raw_title.lower()).strip('-')

    def replace_wikilink(match):
        target = match.group(1).strip()
        display = match.group(2).strip() if match.group(2) else target
        link_slug = re.sub(r'[^a-z0-9]+', '-', target.lower()).strip('-')
        return f"[{display}](/kb/{link_slug})"
    cleaned_content = re.sub(r'\[\[([^\|\]]+)(?:\|([^\]]+))?\]\]', replace_wikilink, post.content)

    author = db.query(User).filter(User.username == "admin").first()
    author_id = author.id if author else 1

    article = db.query(Article).filter(Article.slug == slug).first()
    if not article:
        article = Article(title=raw_title, slug=slug, author_id=author_id)
        db.add(article)

    article.category = post.get("category", "General")
    article.difficulty = post.get("difficulty", "Beginner")
    article.content_markdown = cleaned_content
    article.updated_at = datetime.utcnow()

    raw_tags = post.get("tags", [])
    if isinstance(raw_tags, str): raw_tags = [t.strip() for t in raw_tags.split(",")]

    article.tags = []
    for tag_str in raw_tags:
        clean_name = re.sub(r'[^a-zA-Z0-9_-]', '', tag_str.lower().strip().lstrip('#'))
        if clean_name:
            tag_obj = db.query(Tag).filter(Tag.name == clean_name).first()
            if not tag_obj:
                tag_obj = Tag(name=clean_name)
                db.add(tag_obj)
                db.commit()
            article.tags.append(tag_obj)

    db.commit()
    print(f"✅ Webhook Synced Article: {raw_title} (slug: {slug})")

@app.post("/webhooks/github")
async def github_webhook(request: Request, db: Session = Depends(get_db)):
    raw_body = await request.body()
    signature = request.headers.get("X-Hub-Signature-256")
    
    # Strict secret reading without hardcoded fallback string
    webhook_secret = os.getenv("GITHUB_WEBHOOK_SECRET")
    if not webhook_secret:
        return templates.TemplateResponse(request=request, name="index.html", context={"error": "Webhook Secret Not Configured"}, status_code=500)

    if not verify_github_signature(raw_body, signature, webhook_secret):
        return templates.TemplateResponse(request=request, name="index.html", context={"error": "Invalid Webhook Signature"}, status_code=403)

    payload = await request.json()

    commits = payload.get("commits", [])
    repo_full_name = payload.get("repository", {}).get("full_name")
    ref = payload.get("ref", "")
    branch = ref.replace("refs/heads/", "") if ref else "main"
    github_token = os.getenv("GITHUB_TOKEN")

    for commit in commits:
        modified_files = commit.get("added", []) + commit.get("modified", [])
        for file_path in modified_files:
            if file_path.endswith(".md"):
                raw_url = f"https://raw.githubusercontent.com/{repo_full_name}/{branch}/{file_path}"
                try:
                    headers = {'User-Agent': 'FastAPI-Docs-Webhook'}
                    if github_token: headers['Authorization'] = f'token {github_token}'
                    req = urllib.request.Request(raw_url, headers=headers)
                    with urllib.request.urlopen(req) as resp:
                        md_text = resp.read().decode('utf-8')
                        sync_github_md_file(md_text, file_path, db)
                except Exception as e:
                    print(f"❌ Failed to fetch {raw_url}: {e}")

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
@limiter.limit("1/hour")
def register_user(request: Request, username: str = Form(...), email: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    existing_user = db.query(User).filter((User.email == email) | (User.username == username)).first()
    if existing_user:
        return templates.TemplateResponse(request=request, name="register.html", context={"error": "Username or Email is already registered."})
    new_user = User(username=username, email=email, hashed_password=hash_password(password))
    db.add(new_user)
    db.commit()
    
    response = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    token = create_session_token(new_user.id)
    response.set_cookie(key="session", value=token, httponly=True, samesite="lax")
    return response

@app.post("/auth/login")
@limiter.limit("3/minute")
def login_user(request: Request, email: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if not user or not user.hashed_password or not verify_password(password, user.hashed_password):
        return templates.TemplateResponse(request=request, name="login.html", context={"error": "Invalid email or password."})
    
    response = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    token = create_session_token(user.id)
    response.set_cookie(key="session", value=token, httponly=True, samesite="lax")
    return response

@app.get("/auth/logout")
def logout_user():
    response = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    response.delete_cookie(key="session")
    return response

# --- UNIVERSAL TRANSACTIONAL EMAIL SENDER ---

def send_verification_email(to_email: str, username: str, token: str):
    resend_api_key = os.getenv("RESEND_API_KEY")
    domain = os.getenv("DOMAIN", "askpc.cc")
    verify_url = f"https://{domain}/verify-email?token={token}"

    # Fallback for local dev if no API key is specified in .env
    if not resend_api_key:
        print(f"\n📧 [LOCAL DEV LOG] VERIFICATION LINK FOR @{username}: http://localhost:8000/verify-email?token={token}\n")
        return

    # Send real email via Resend API (Free 300 emails/day)
    try:
        payload = json.dumps({
            "from": f"askpc.cc <noreply@{domain}>",
            "to": [to_email],
            "subject": "Verify your email address on askpc.cc",
            "html": f"""
                <div style="font-family: sans-serif; max-width: 500px; margin: 0 auto; padding: 20px; border: 1px solid #e5e5e5; border-radius: 4px;">
                    <h2>Welcome to askpc.cc, @{username}!</h2>
                    <p>Please confirm your email address by clicking the link below:</p>
                    <p><a href="{verify_url}" style="display: inline-block; padding: 10px 20px; background: #111; color: #fff; text-decoration: none; border-radius: 4px;">Verify Email Address</a></p>
                    <p style="font-size: 0.8rem; color: #666;">Or copy this link: {verify_url}</p>
                </div>
            """
        }).encode('utf-8')

        req = urllib.request.Request(
            "https://api.resend.com/emails",
            data=payload,
            headers={
                "Authorization": f"Bearer {resend_api_key}",
                "Content-Type": "application/json",
                "User-Agent": "FastAPI-Mailer"
            },
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            print(f"✅ Real verification email sent to {to_email}")
    except Exception as e:
        print(f"❌ Failed to send email via API: {e}")
