"""
Manual GitHub content re-sync, run directly on the server — no HTTP,
no auth cookie, no CSRF dance. Walks the whole repo tree and (re-)syncs
every .md file under wiki/ or docs/, same logic as /admin/github/sync.

Usage (from the host):
    docker compose exec web python -m app.sync_cli
    docker compose exec web python -m app.sync_cli --dry-run
"""
import argparse
import os
import sys

import requests

from .database import SessionLocal
from .main import (
    GITHUB_REPO,
    GITHUB_SYNC_BRANCH,
    SYNC_DIRECTORIES,
    sync_github_md_file,
    sync_github_wiki_file,
)


def run_sync(dry_run: bool = False) -> int:
    if not GITHUB_REPO:
        print("❌ GITHUB_REPO env var not set (expected 'owner/repo').")
        return 1

    github_token = os.getenv("GITHUB_TOKEN")
    headers = {"User-Agent": "FastAPI-Docs-Sync-CLI"}
    if github_token:
        headers["Authorization"] = f"token {github_token}"
    else:
        print("⚠️  GITHUB_TOKEN not set — limited to 60 req/hour on the GitHub API.")

    tree_url = (
        f"https://api.github.com/repos/{GITHUB_REPO}/git/trees/"
        f"{GITHUB_SYNC_BRANCH}?recursive=1"
    )
    try:
        resp = requests.get(tree_url, headers=headers, timeout=15)
        resp.raise_for_status()
        tree = resp.json().get("tree", [])
    except Exception as e:
        print(f"❌ Failed to fetch repo tree: {e}")
        return 1

    targets = [
        e["path"]
        for e in tree
        if e.get("type") == "blob"
        and e["path"].endswith(".md")
        and e["path"].startswith(SYNC_DIRECTORIES)
    ]

    print(f"Found {len(targets)} file(s) under {SYNC_DIRECTORIES}:")
    for path in targets:
        print(f"  - {path}")

    if dry_run:
        print("\n(dry-run: nothing synced)")
        return 0

    db = SessionLocal()
    synced, failed = [], []
    try:
        for path in targets:
            raw_url = (
                f"https://raw.githubusercontent.com/{GITHUB_REPO}/"
                f"{GITHUB_SYNC_BRANCH}/{path}"
            )
            try:
                raw_resp = requests.get(raw_url, headers=headers, timeout=15)
                raw_resp.raise_for_status()
                md_text = raw_resp.text

                if path.startswith("wiki/"):
                    sync_github_wiki_file(md_text, path, db)
                else:
                    sync_github_md_file(md_text, path, db)
                synced.append(path)
                print(f"✅ synced: {path}")
            except Exception as e:
                failed.append(path)
                print(f"❌ failed: {path} — {e}")
    finally:
        db.close()

    print(f"\nDone: {len(synced)} synced, {len(failed)} failed.")
    return 1 if failed else 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Manual GitHub content sync")
    parser.add_argument(
        "--dry-run", action="store_true", help="List matching files without syncing"
    )
    args = parser.parse_args()
    sys.exit(run_sync(dry_run=args.dry_run))
