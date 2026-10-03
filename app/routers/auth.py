"""Email/password auth: register, login, logout, email verification, password reset."""
import secrets
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Form, Request
from sqlalchemy.orm import Session

from ..auth import hash_password, verify_password
from ..core import limiter, templates
from ..database import get_db
from ..deps import redirect, set_auth_cookie
from ..models import User
from ..services.email import send_reset_password_email, send_verification_email
from ..services.tokens import hash_token, issue_token
from ..config import REGISTRATION_OPEN

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
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    if not REGISTRATION_OPEN:
        return _render(request, "register.html", error="Registration is temporarily closed.")
    exists = (
        db.query(User)
        .filter((User.email == email) | (User.username == username))
        .first()
    )
    if exists:
        return _render(request, "register.html", error="Username or Email is already registered.")

    new_user = User(username=username, email=email, hashed_password=hash_password(password))
    db.add(new_user)
    db.commit()

    raw_token, token_hash = issue_token()
    new_user.email_verification_token = token_hash
    db.commit()
    send_verification_email(new_user.email, new_user.username, raw_token)

    response = redirect("/")
    set_auth_cookie(response, new_user)
    return response


@router.post("/auth/login")
@limiter.limit("5/minute")
def login_user(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.email == email).first()

    # Always verify against *some* hash so timing doesn't reveal registered emails.
    hash_to_check = user.hashed_password if (user and user.hashed_password) else DUMMY_HASH
    password_ok = verify_password(password, hash_to_check)

    if not user or not user.hashed_password or not password_ok:
        return _render(request, "login.html", error="Invalid email or password.")

    response = redirect("/")
    set_auth_cookie(response, user)
    return response


@router.get("/auth/logout")
def logout_user():
    response = redirect("/")
    response.delete_cookie(key="auth_session")
    return response


# --- email verification ---


@router.get("/verify-email")
def verify_email(token: str, request: Request, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email_verification_token == hash_token(token)).first()
    if not user:
        return _render(request, "settings.html", error="Invalid or expired verification token.")
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
    user = db.query(User).filter(User.email == email.strip()).first()
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
