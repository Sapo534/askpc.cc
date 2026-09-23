"""GitHub OAuth: login, account linking, unlinking."""
from typing import Optional

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from ..config import get_domain
from ..core import oauth
from ..database import get_db
from ..deps import get_current_user, redirect, set_auth_cookie
from ..models import User

router = APIRouter()


async def _fetch_identity(token) -> dict:
    """GitHub login/avatar + the best email we can find and whether GitHub verified it."""
    profile = (await oauth.github.get("user", token=token)).json()

    email: Optional[str] = profile.get("email")
    email_verified = False
    if email:
        # A public profile email is only exposed for verified addresses.
        email_verified = True
    else:
        emails = (await oauth.github.get("user/emails", token=token)).json()
        primary = next((e for e in emails if e.get("primary")), None)
        if primary:
            email = primary.get("email")
            email_verified = bool(primary.get("verified"))

    return {
        "username": profile.get("login"),
        "avatar": profile.get("avatar_url"),
        "email": email,
        "email_verified": email_verified,
    }


def _unique_username(db: Session, base: str) -> str:
    candidate, counter = base, 1
    while db.query(User).filter(User.username == candidate).first():
        counter += 1
        candidate = f"{base}{counter}"
    return candidate


@router.get("/auth/github")
@router.get("/settings/github/link")
async def github_login(request: Request):
    redirect_uri = f"https://{get_domain()}/auth/github/callback"
    return await oauth.github.authorize_redirect(request, redirect_uri)


@router.get("/auth/github/callback")
async def github_callback(request: Request, db: Session = Depends(get_db)):
    try:
        token = await oauth.github.authorize_access_token(request)
        gh = await _fetch_identity(token)
        gh_username, avatar, email = gh["username"], gh["avatar"], gh["email"]
        email_verified = gh["email_verified"]

        if not email:
            return redirect("/login?error=GitHub+account+has+no+verified+email")

        current_user = get_current_user(request, db)

        # --- Case 1: logged-in user linking GitHub to their account ---
        if current_user:
            taken = (
                db.query(User)
                .filter(User.github_username == gh_username, User.id != current_user.id)
                .first()
            )
            if taken:
                return redirect(
                    f"/settings?error=GitHub+account+@{gh_username}+is+already+linked+to+another+user"
                )

            current_user.github_username = gh_username
            # Only trust GitHub's verification for the *same* address.
            if email_verified and current_user.email == email:
                current_user.is_email_verified = True
            if current_user.avatar_url == "/static/default-avatar.png" and avatar:
                current_user.avatar_url = avatar

            db.commit()
            return redirect(f"/settings?message=GitHub+account+@{gh_username}+linked+successfully!")

        # --- Case 2: fresh GitHub login ---
        # Match only by linked GitHub username or a VERIFIED email; never by username.
        user = db.query(User).filter(User.github_username == gh_username).first()
        if not user and email_verified:
            user = db.query(User).filter(User.email == email).first()

        if not user:
            user = User(
                username=_unique_username(db, gh_username),
                github_username=gh_username,
                email=email,
                avatar_url=avatar,
                is_email_verified=email_verified,
            )
            db.add(user)
            db.commit()
            db.refresh(user)
        else:
            if not user.github_username:
                user.github_username = gh_username
            if email_verified:
                user.is_email_verified = True
            db.commit()

        response = redirect("/")
        set_auth_cookie(response, user)
        return response

    except Exception as e:
        print(f"❌ GitHub OAuth Callback Error: {e}")
        return redirect("/login?error=OAuth+failed")


@router.post("/settings/github/unlink")
def unlink_github(request: Request, db: Session = Depends(get_db)):
    current_user = get_current_user(request, db)
    if not current_user:
        return redirect("/login")

    # Never leave the account without a login method.
    if not current_user.hashed_password:
        return redirect(
            "/settings?error=Cannot+unlink+GitHub+-+you+have+no+password+set."
            "+Please+set+a+password+first."
        )

    current_user.github_username = None
    db.commit()
    return redirect("/settings?message=GitHub+account+unlinked")
