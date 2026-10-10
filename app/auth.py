import os
import secrets
import hashlib
from pathlib import Path
import bcrypt
from itsdangerous import URLSafeTimedSerializer
from typing import Optional

# 1. SECURITY: STRICT SECRET KEY — persisted, not regenerated per-restart
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    print("⚠️  SECRET_KEY not set in .env — using/generating .secret_key on disk")
    key_file = Path(".secret_key")
    if key_file.exists():
        SECRET_KEY = key_file.read_text().strip()
    else:
        SECRET_KEY = secrets.token_urlsafe(64)
        key_file.write_text(SECRET_KEY)
        key_file.chmod(0o600)

serializer = URLSafeTimedSerializer(
    SECRET_KEY, signer_kwargs={"digest_method": hashlib.sha256}
)


def hash_password(password: str) -> str:
    pwd_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(
        plain_password.encode("utf-8"), hashed_password.encode("utf-8")
    )


def create_session_token(user_id: int, session_version: str, remember: bool = False) -> str:
    return serializer.dumps({"user_id": user_id, "sv": session_version, "rem": remember})



