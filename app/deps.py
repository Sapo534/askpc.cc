"""Request-level helpers shared by routers: current user, admin check, cookies."""
from typing import Optional

from fastapi import Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from .auth import create_session_token, serializer
from .config import MAX_AGE_30_DAYS
from .models import User
from .services.sponsors import refresh_sponsor_status


def redirect(url: str) -> RedirectResponse:
    return RedirectResponse(url=url, status_code=status.HTTP_302_FOUND)


def get_current_user(request: Request, db: Session) -> Optional[User]:
    token = request.cookies.get("auth_session")
    if not token:
        return None

    # Decode without trusting "sv" yet — we need the user row to know
    # their CURRENT session_version to compare against.
    try:
        data = serializer.loads(token, max_age=MAX_AGE_30_DAYS)
    except Exception:
        return None

    user = db.query(User).filter(User.id == data.get("user_id")).first()
    if not user:
        return None

    # A stale session_version means this cookie predates a password change /
    # logout-everywhere / reset — treat it as invalid.
    if data.get("sv") != user.session_version:
        return None

    if refresh_sponsor_status(user):
        db.commit()
    return user


def require_admin(user: Optional[User]) -> bool:
    return bool(user and user.system_role in ("founder", "co_founder", "admin"))


def set_auth_cookie(response: Response, user: User) -> None:
    response.set_cookie(
        key="auth_session",
        value=create_session_token(user.id, user.session_version),
        max_age=MAX_AGE_30_DAYS,
        httponly=True,
        samesite="lax",
        secure=True,
    )
