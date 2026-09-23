from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from ..config import SPONSOR_GOAL, SPONSOR_PERIOD_DAYS
from ..models import User


def now_utc() -> datetime:
    """Naive UTC 'now', matching the rest of the codebase's datetime usage."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def count_active_sponsors(db: Session) -> int:
    return (
        db.query(User)
        .filter(
            User.is_sponsor == True,  # noqa: E712
            User.sponsor_until.isnot(None),
            User.sponsor_until > now_utc(),
        )
        .count()
    )


def sponsor_stats(db: Session) -> dict:
    """Template context for the community page progress bar."""
    count = count_active_sponsors(db)
    return {
        "active_sponsors_count": count,
        "progress_percent": min(100, int((count / SPONSOR_GOAL) * 100)),
    }


def refresh_sponsor_status(user: User) -> bool:
    """Downgrade the user if sponsor_until has passed. True if mutated."""
    if user.is_sponsor and user.sponsor_until and user.sponsor_until <= now_utc():
        user.is_sponsor = False
        return True
    return False


def extend_sponsorship(user: User, days: int = SPONSOR_PERIOD_DAYS) -> None:
    now = now_utc()
    base = max(user.sponsor_until or now, now)
    user.is_sponsor = True
    user.sponsor_until = base + timedelta(days=days)
