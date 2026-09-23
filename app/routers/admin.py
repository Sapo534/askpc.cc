"""Admin-only tools."""
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ..config import GITHUB_REPO, GITHUB_SYNC_BRANCH
from ..core import limiter
from ..database import get_db
from ..deps import get_current_user, require_admin
from ..schemas import SyncResult
from ..services.github import (
    fetch_raw_markdown,
    list_repo_markdown_paths,
    sync_markdown_file,
)

router = APIRouter()


@router.post("/admin/github/sync", response_model=SyncResult)
@limiter.limit("5/hour")
def manual_github_sync(request: Request, db: Session = Depends(get_db)):
    """Walk the whole repo tree (not just the latest diff) and re-sync every .md
    under wiki/ or docs/. Handy for the first sync or after a missed webhook."""
    if not require_admin(get_current_user(request, db)):
        raise HTTPException(status_code=403, detail="Admin access required.")

    if not GITHUB_REPO:
        raise HTTPException(
            status_code=500, detail="GITHUB_REPO env var not set (expected 'owner/repo')."
        )

    try:
        paths = list_repo_markdown_paths(GITHUB_REPO, GITHUB_SYNC_BRANCH)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Failed to fetch repo tree from GitHub: {e}")

    synced, failed = [], []
    for path in paths:
        try:
            sync_markdown_file(path, fetch_raw_markdown(GITHUB_REPO, GITHUB_SYNC_BRANCH, path), db)
            synced.append(path)
        except Exception as e:
            db.rollback()
            print(f"❌ Manual sync failed for {path}: {e}")
            failed.append(path)

    return {"synced": synced, "failed": failed, "total": len(synced) + len(failed)}
