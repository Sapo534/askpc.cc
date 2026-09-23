"""GitHub push webhook -> automatic wiki/docs sync."""
import os

from fastapi import APIRouter, Depends, Request
from fastapi.concurrency import run_in_threadpool
from sqlalchemy.orm import Session

from ..core import templates
from ..database import get_db
from ..schemas import WebhookResult
from ..services.github import (
    delete_markdown_file,
    fetch_raw_markdown,
    is_syncable_path,
    sync_markdown_file,
    verify_github_signature,
)

router = APIRouter()


def _error(request: Request, message: str, status_code: int):
    return templates.TemplateResponse(
        request=request, name="index.html", context={"error": message}, status_code=status_code
    )


def _process_push(payload: dict, db: Session) -> None:
    """Blocking work (HTTP + DB); runs in a worker thread, not on the event loop."""
    repo = payload.get("repository", {}).get("full_name")
    ref = payload.get("ref", "")
    branch = ref.replace("refs/heads/", "") if ref else "main"

    for commit in payload.get("commits", []):
        for path in commit.get("added", []) + commit.get("modified", []):
            if not is_syncable_path(path):
                continue
            try:
                sync_markdown_file(path, fetch_raw_markdown(repo, branch, path), db)
            except Exception as e:
                db.rollback()
                print(f"❌ Failed to sync {path}: {e}")

        for path in commit.get("removed", []):
            if is_syncable_path(path):
                delete_markdown_file(path, db)


@router.post("/webhooks/github", response_model=WebhookResult)
async def github_webhook(request: Request, db: Session = Depends(get_db)):
    raw_body = await request.body()
    secret = os.getenv("GITHUB_WEBHOOK_SECRET")
    if not secret:
        return _error(request, "Webhook Secret Not Configured", 500)

    if not verify_github_signature(raw_body, request.headers.get("X-Hub-Signature-256"), secret):
        return _error(request, "Invalid Webhook Signature", 403)

    payload = await request.json()
    await run_in_threadpool(_process_push, payload, db)
    return {"status": "success", "synced": True}
