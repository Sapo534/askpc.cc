import hashlib
import secrets
from typing import Tuple


def hash_token(token: str) -> str:
    """One-way fingerprint for verification/reset tokens stored in the DB.
    Only the hash is stored, so a DB dump alone can't be used to take over
    accounts through these tokens."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def issue_token() -> Tuple[str, str]:
    """Returns (raw_token_for_the_email, hash_to_store_in_db)."""
    raw = secrets.token_urlsafe(32)
    return raw, hash_token(raw)
