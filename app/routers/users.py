"""User settings, security changes and public profiles."""
import secrets
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from sqlalchemy.orm import Session

from ..auth import hash_password, verify_password
from ..core import templates
from ..database import get_db
from ..deps import get_current_user, redirect
from ..models import ForumThread, User
from ..services.email import send_verification_email
from ..services.files import save_secure_file
from ..services.tokens import issue_token

router = APIRouter()

CHANGE_COOLDOWN = timedelta(days=14)


def _settings_page(request: Request, user, **extra):
    return templates.TemplateResponse(
        request=request, name="settings.html", context={"user": user, **extra}
    )


def _cooldown_error(last_change: Optional[datetime], what: str) -> Optional[str]:
    if last_change and last_change > datetime.utcnow() - CHANGE_COOLDOWN:
        next_date = (last_change + CHANGE_COOLDOWN).strftime("%Y-%m-%d")
        return f"{what} can only be changed once every 14 days. Next available on {next_date}."
    return None


@router.get("/settings")
def settings_page(request: Request, db: Session = Depends(get_db)):
    current_user = get_current_user(request, db)
    if not current_user:
        return redirect("/login")
    return _settings_page(request, current_user)


@router.post("/settings")
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
        return redirect("/login")

    if experience_badge in ["Teapot", "User", "Pro"]:
        current_user.experience_badge = experience_badge

    current_user.bio = bio.strip()[:1000] if bio else None

    if avatar and avatar.filename:
        try:
            avatar_url, _ = save_secure_file(avatar, "avatars")
            if avatar_url:
                current_user.avatar_url = avatar_url
        except ValueError as err:
            return _settings_page(request, current_user, error=str(err))

    can_customize = current_user.is_sponsor or current_user.system_role in [
        "founder", "co_founder", "admin",
    ]
    if can_customize and custom_color:
        current_user.custom_color = custom_color

    db.commit()
    return _settings_page(request, current_user, message="Settings updated successfully!")


@router.post("/settings/security/username")
def change_username(
    request: Request, new_username: str = Form(...), db: Session = Depends(get_db)
):
    current_user = get_current_user(request, db)
    if not current_user:
        return redirect("/login")

    error = _cooldown_error(current_user.last_username_change, "Username")
    if error:
        return _settings_page(request, current_user, error=error)

    taken = (
        db.query(User)
        .filter(User.username == new_username, User.id != current_user.id)
        .first()
    )
    if taken:
        return _settings_page(request, current_user, error="Username is already taken.")

    current_user.username = new_username.strip()
    current_user.last_username_change = datetime.utcnow()
    db.commit()
    return _settings_page(request, current_user, message="Username updated successfully!")


@router.post("/settings/security/email")
def change_email(
    request: Request, new_email: str = Form(...), db: Session = Depends(get_db)
):
    current_user = get_current_user(request, db)
    if not current_user:
        return redirect("/login")

    error = _cooldown_error(current_user.last_email_change, "Email")
    if error:
        return _settings_page(request, current_user, error=error)

    taken = (
        db.query(User)
        .filter(User.email == new_email, User.id != current_user.id)
        .first()
    )
    if taken:
        return _settings_page(request, current_user, error="Email is already registered.")

    raw_token, token_hash = issue_token()
    current_user.email = new_email.strip()
    current_user.is_email_verified = False
    current_user.email_verification_token = token_hash
    current_user.last_email_change = datetime.utcnow()
    db.commit()
    send_verification_email(new_email.strip(), current_user.username, raw_token)
    return _settings_page(request, current_user, message="Email updated! Verification link sent.")


@router.post("/settings/security/password")
def change_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    db: Session = Depends(get_db),
):
    current_user = get_current_user(request, db)
    if not current_user:
        return redirect("/login")

    if not current_user.hashed_password or not verify_password(
        current_password, current_user.hashed_password
    ):
        return _settings_page(request, current_user, error="Current password is incorrect.")

    error = _cooldown_error(current_user.last_password_change, "Password")
    if error:
        return _settings_page(request, current_user, error=error)

    current_user.hashed_password = hash_password(new_password)
    current_user.last_password_change = datetime.utcnow()
    # Kills every active session (this one included).
    current_user.session_version = secrets.token_hex(8)
    db.commit()

    response = _settings_page(
        request, current_user, message="Password updated successfully! Please log in again."
    )
    response.delete_cookie(key="auth_session")
    return response


@router.post("/settings/security/logout-everywhere")
def logout_everywhere(request: Request, db: Session = Depends(get_db)):
    current_user = get_current_user(request, db)
    if not current_user:
        return redirect("/login")

    current_user.session_version = secrets.token_hex(8)
    db.commit()

    response = redirect("/settings?message=Logged+out+everywhere.+Please+log+in+again.")
    response.delete_cookie(key="auth_session")
    return response


@router.get("/u/{username}")
def public_profile(username: str, request: Request, db: Session = Depends(get_db)):
    profile_user = db.query(User).filter(User.username == username).first()
    if not profile_user:
        return redirect("/")
    threads = db.query(ForumThread).filter(ForumThread.author_id == profile_user.id).all()
    return templates.TemplateResponse(
        request=request,
        name="profile.html",
        context={
            "user": get_current_user(request, db),
            "profile_user": profile_user,
            "threads": threads,
        },
    )
