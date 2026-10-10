"""Email/password auth: register, login, logout, email verification, password reset."""
import re
import secrets
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Form, Request
from sqlalchemy.orm import Session
from sqlalchemy import func

from ..antibot import check_challenge, email_budget_ok
from ..auth import hash_password, verify_password
from ..core import limiter, templates
from ..database import get_db
from ..deps import redirect, set_auth_cookie, get_current_user
from ..models import User
from ..services.email import send_reset_password_email, send_verification_email
from ..services.tokens import hash_token, issue_token
from ..config import REGISTRATION_OPEN

USERNAME_RE = re.compile(r"[A-Za-z0-9_-]{3,32}")
EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")

router = APIRouter()

# Dummy bcrypt hash keeps /auth/login timing constant whether or not the email
# exists (mitigates user enumeration).
DUMMY_HASH = hash_password("dummy_password_never_used_1234567890")


def _render(request: Request, name: str, **context):
    return templates.TemplateResponse(request=request, name=name, context=context)


def _find_user_by_reset_token(db: Session, token: str):
    """Valid (non-expired) reset-token owner, else None."""
    user = db.query(User).filter(User.reset_password_token == hash_token(token)).first()
    if not user or not user.reset_password_expiry or user.reset_password_expiry < datetime.utcnow():
        return None
    return user


# --- pages ---


@router.get("/login")
@router.get("/login.html")
def login_page(request: Request):
    return _render(request, "login.html")


@router.get("/register")
@router.get("/register.html")
def register_page(request: Request):
    if not REGISTRATION_OPEN:
        return _render(request, "register.html", error="Registration is temporarily closed.")
    return _render(request, "register.html")


# --- register / login / logout ---


@router.post("/auth/register")
@limiter.limit("5/hour")
def register_user(
    request: Request,
    remember: bool = Form(False),
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    website: str = Form(""),       # honeypot
    challenge: str = Form(""),
    pow_nonce: str = Form(""),
    db: Session = Depends(get_db),
):
    if not REGISTRATION_OPEN:
        return _render(request, "register.html", error="Registration is temporarily closed.")

    problem = check_challenge(challenge, pow_nonce, website)
    if problem:
        return _render(request, "register.html", error=problem)

    username = username.strip()
    email = email.strip().lower()
    if not USERNAME_RE.fullmatch(username):
        return _render(request, "register.html", error="Username: 3-32 characters, letters, digits, _ or -.")
    if len(email) > 254 or not EMAIL_RE.fullmatch(email):
        return _render(request, "register.html", error="Please enter a valid email address.")
    if not 8 <= len(password) <= 128:
        return _render(request, "register.html", error="Password must be 8-128 characters.")

    exists = (
        db.query(User)
        .filter((func.lower(User.email) == email) | (func.lower(User.username) == username.lower()))
        .first()
    )
    if exists:
        return _render(request, "register.html", error="Username or Email is already registered.")

    if not email_budget_ok():
        return _render(request, "register.html", error="Too many sign-ups right now. Please try again later.")

    new_user = User(username=username, email=email, hashed_password=hash_password(password))
    db.add(new_user)
    db.commit()

    raw_token, token_hash = issue_token()
    new_user.email_verification_token = token_hash
    db.commit()
    send_verification_email(new_user.email, new_user.username, raw_token)

    response = redirect("/")
    set_auth_cookie(response, new_user, remember)
    return response

@router.post("/auth/login")
@limiter.limit("5/minute")
def login_user(
    request: Request,
    remember: bool = Form(False),
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(func.lower(User.email) == email.strip().lower()).first()

    # Always verify against *some* hash so timing doesn't reveal registered emails.
    hash_to_check = user.hashed_password if (user and user.hashed_password) else DUMMY_HASH
    password_ok = verify_password(password, hash_to_check)

    if not user or not user.hashed_password or not password_ok:
        return _render(request, "login.html", error="Invalid email or password.")

    response = redirect("/")
    set_auth_cookie(response, user, login)
    return response


@router.get("/auth/logout")
def logout_user():
    response = redirect("/")
    response.delete_cookie(key="auth_session")
    return response


# --- email verification ---

@router.get("/verify-email")
def verify_email_page(token: str, request: Request, db: Session = Depends(get_db)):
    # GET only shows a button: mail scanners that prefetch links must not consume the token.
    user = db.query(User).filter(User.email_verification_token == hash_token(token)).first()
    if not user:
        return redirect("/settings?error=Invalid+or+expired+verification+link.+Request+a+new+one+in+Settings.")
    return templates.TemplateResponse(
        request=request,
        name="verify_email.html",
        context={"user": get_current_user(request, db), "token": token},
    )


@router.post("/verify-email")
@limiter.limit("20/hour")
def verify_email(request: Request, token: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email_verification_token == hash_token(token)).first()
    if not user:
        return redirect("/settings?error=Invalid+or+expired+verification+link.+Request+a+new+one+in+Settings.")
    user.is_email_verified = True
    user.email_verification_token = None
    db.commit()
    return redirect("/settings?message=Email+verified+successfully!")

# --- password reset ---


@router.get("/forgot-password")
def forgot_password_page(request: Request):
    return _render(request, "forgot_password.html")


@router.post("/forgot-password")
@limiter.limit("3/hour")
def process_forgot_password(
    request: Request, email: str = Form(...), db: Session = Depends(get_db)
):
    user = db.query(User).filter(func.lower(User.email) == email.strip().lower()).first()
    if user:
        raw_token, token_hash = issue_token()
        user.reset_password_token = token_hash
        user.reset_password_expiry = datetime.utcnow() + timedelta(hours=1)
        db.commit()
        send_reset_password_email(user.email, user.username, raw_token)

    # Same response either way — no account enumeration.
    return _render(
        request,
        "forgot_password.html",
        message="If an account with that email exists, a password reset link has been sent.",
    )


@router.get("/reset-password")
def reset_password_page(token: str, request: Request, db: Session = Depends(get_db)):
    if not _find_user_by_reset_token(db, token):
        return _render(request, "forgot_password.html", error="Invalid or expired password reset link.")
    return _render(request, "reset_password.html", token=token)


@router.post("/reset-password")
def process_reset_password(
    request: Request,
    token: str = Form(...),
    new_password: str = Form(...),
    db: Session = Depends(get_db),
):
    user = _find_user_by_reset_token(db, token)
    if not user:
        return _render(request, "forgot_password.html", error="Invalid or expired password reset link.")

    user.hashed_password = hash_password(new_password)
    user.reset_password_token = None
    user.reset_password_expiry = None
    user.last_password_change = datetime.utcnow()
    # A reset usually means "someone else may have access": nuke every session.
    user.session_version = secrets.token_hex(8)
    db.commit()

    return redirect("/login?message=Password+reset+successful!+Please+log+in.")
