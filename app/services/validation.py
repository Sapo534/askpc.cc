"""Shared input validation. Each function returns an error message, or None if OK."""
import re

USERNAME_RE = re.compile(r"[A-Za-z0-9_-]{3,32}")
EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")


def username_error(username: str) -> str | None:
    if not USERNAME_RE.fullmatch(username):
        return "Username: 3-32 characters, letters, digits, _ or -."
    return None


def email_error(email: str) -> str | None:
    if len(email) > 254 or not EMAIL_RE.fullmatch(email):
        return "Please enter a valid email address."
    return None


def password_error(password: str) -> str | None:
    if not 8 <= len(password) <= 128:
        return "Password must be 8-128 characters."
    # bcrypt only uses the first 72 bytes and newer versions reject longer input.
    if len(password.encode("utf-8")) > 72:
        return "Password is too long (at most 72 bytes; non-Latin characters take more than one)."
    return None
