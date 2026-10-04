"""Cheap anti-bot helpers for the sign-up form."""
import hashlib
import os
import secrets
import threading
import time
from collections import deque
from datetime import datetime, timezone

from itsdangerous import BadSignature, URLSafeTimedSerializer

POW_BITS = 18            # ~260k hashes on average: a second or two in a browser
MIN_FILL_SECONDS = 2     # humans can't fill a form faster
MAX_AGE_SECONDS = 3600   # a challenge lives one hour
EMAILS_PER_HOUR = 20     # global cap on verification emails

_serializer = URLSafeTimedSerializer(os.environ["SECRET_KEY"], salt="register-challenge")
_lock = threading.Lock()
_used: dict[str, float] = {}
_sent: deque[float] = deque()


def new_challenge() -> dict:
    salt = secrets.token_hex(16)
    return {"salt": salt, "token": _serializer.dumps(salt), "bits": POW_BITS}


def _leading_zero_bits(digest: bytes) -> int:
    bits = 0
    for byte in digest:
        if byte == 0:
            bits += 8
            continue
        bits += 8 - byte.bit_length()
        break
    return bits


def check_challenge(token: str, nonce: str, honeypot: str) -> str | None:
    """Return an error message, or None when the form looks human."""
    fail = "Verification failed. Please reload the page and try again."
    if honeypot:
        return fail
    try:
        salt, issued = _serializer.loads(token, max_age=MAX_AGE_SECONDS, return_timestamp=True)
    except BadSignature:
        return fail
    if (datetime.now(timezone.utc) - issued).total_seconds() < MIN_FILL_SECONDS:
        return fail
    if not (nonce.isdigit() and len(nonce) <= 12):
        return fail
    digest = hashlib.sha256(f"{salt}:{nonce}".encode()).digest()
    if _leading_zero_bits(digest) < POW_BITS:
        return fail
    now = time.time()
    with _lock:
        for key in [k for k, exp in _used.items() if exp < now]:
            del _used[key]
        if salt in _used:  # replay of an already-solved challenge
            return fail
        _used[salt] = now + MAX_AGE_SECONDS
    return None


def email_budget_ok() -> bool:
    now = time.time()
    with _lock:
        while _sent and _sent[0] < now - 3600:
            _sent.popleft()
        if len(_sent) >= EMAILS_PER_HOUR:
            return False
        _sent.append(now)
        return True
