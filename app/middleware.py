"""CSRF origin check + security headers."""
from urllib.parse import urlparse

from fastapi import Request

from .config import ALLOWED_HOSTS
from .core import templates

# Webhook is authenticated by HMAC signature instead of an Origin header.
CSRF_EXEMPT_PATHS = {"/webhooks/github"}

CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data: https:;"
)


def _csrf_error(request: Request, message: str):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"error": message},
        status_code=403,
    )


async def security_headers_and_csrf(request: Request, call_next):
    if request.method in ("POST", "PUT", "DELETE") and request.url.path not in CSRF_EXEMPT_PATHS:
        origin = request.headers.get("origin") or request.headers.get("referer")
        if not origin:
            return _csrf_error(request, "CSRF Validation Failed: Missing origin header.")
        if urlparse(origin).netloc not in ALLOWED_HOSTS:
            return _csrf_error(request, "CSRF Validation Failed: Request origin not allowed.")

    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Content-Security-Policy"] = CSP
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response
