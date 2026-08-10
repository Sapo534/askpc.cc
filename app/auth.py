import os
import secrets
import bcrypt
from itsdangerous import URLSafeTimedSerializer
from typing import Optional

# 1. SECURITY: STRICT SECRET KEY WITHOUT PUBLIC FALLBACKS
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    # Random cryptographic key generated per server runtime if not specified in .env
    SECRET_KEY = secrets.token_urlsafe(64)

serializer = URLSafeTimedSerializer(SECRET_KEY)

def hash_password(password: str) -> str:
    pwd_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def create_session_token(user_id: int) -> str:
    return serializer.dumps({"user_id": user_id})

def verify_session_token(token: str, max_age: int = 60 * 60 * 24 * 30) -> Optional[int]:
    try:
        data = serializer.loads(token, max_age=max_age)
        return data.get("user_id")
    except Exception:
        return None
