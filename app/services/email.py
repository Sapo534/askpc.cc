"""Transactional email via Resend. Without RESEND_API_KEY the link is printed (dev)."""
import html
import os

import requests

from ..config import get_domain

_RESEND_URL = "https://api.resend.com/emails"


def _card(body: str) -> str:
    return (
        '<div style="font-family: sans-serif; max-width: 500px; margin: 0 auto; '
        'padding: 20px; border: 1px solid #e5e5e5; border-radius: 4px;">'
        f"{body}</div>"
    )


def _button(url: str, label: str) -> str:
    return (
        f'<p><a href="{url}" style="display: inline-block; padding: 10px 20px; '
        "background: #111; color: #fff; text-decoration: none; "
        f'border-radius: 4px;">{label}</a></p>'
    )


def _send(*, to_email: str, subject: str, html_body: str, dev_log: str, ok_log: str) -> None:
    api_key = os.getenv("RESEND_API_KEY")
    if not api_key:
        print(dev_log)
        return
    try:
        response = requests.post(
            _RESEND_URL,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            },
            json={
                "from": f"askpc.cc <noreply@{get_domain()}>",
                "to": [to_email],
                "subject": subject,
                "html": html_body,
            },
            timeout=15,
        )
        if response.status_code in (200, 201):
            print(ok_log)
        else:
            print(f"❌ Resend API Error {response.status_code}: {response.text}")
    except Exception as e:
        print(f"❌ Failed to send email via API: {e}")


def send_verification_email(to_email: str, username: str, token: str) -> None:
    url = f"https://{get_domain()}/verify-email?token={token}"
    name = html.escape(username)  # usernames are user-controlled
    _send(
        to_email=to_email,
        subject="Verify your email address on askpc.cc",
        html_body=_card(
            f"<h2>Welcome to askpc.cc, @{name}!</h2>"
            "<p>Please confirm your email address by clicking the link below:</p>"
            + _button(url, "Verify Email Address")
        ),
        dev_log=f"\n📧 [LOCAL DEV LOG] VERIFICATION LINK FOR @{username}: "
        f"http://localhost:8000/verify-email?token={token}\n",
        ok_log=f"✅ Real verification email sent to {to_email}",
    )


def send_reset_password_email(to_email: str, username: str, token: str) -> None:
    url = f"https://{get_domain()}/reset-password?token={token}"
    name = html.escape(username)
    _send(
        to_email=to_email,
        subject="Password Reset Request for askpc.cc",
        html_body=_card(
            "<h2>Password Reset Request</h2>"
            f"<p>Hi @{name}, click the link below to set a new password. "
            "Link is valid for 1 hour:</p>" + _button(url, "Set New Password")
        ),
        dev_log=f"\n🔑 [LOCAL DEV LOG] RESET PASSWORD LINK FOR @{username}: "
        f"http://localhost:8000/reset-password?token={token}\n",
        ok_log=f"🔑 Password reset email sent to {to_email}",
    )
