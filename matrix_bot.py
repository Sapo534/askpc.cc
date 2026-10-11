import asyncio
import os
import sys

from nio import (
    AsyncClient,
    InviteMemberEvent,
    LoginError,
    MatrixRoom,
    RoomMessageText,
    SyncError,
)

from app.database import SessionLocal
from app.models import ForumReply, ForumThread, User

HOMESERVER = os.getenv("MATRIX_HOMESERVER", "https://matrix.askpc.cc")
BOT_USER = os.getenv("MATRIX_BOT_USER", "")
BOT_PASS = os.getenv("MATRIX_BOT_PASSWORD", "")
# Comma-separated Matrix IDs allowed to use the bot, e.g. "@you:askpc.cc".
# Everyone else is ignored: lookups reveal emails and other private data.
ADMINS = {a.strip() for a in os.getenv("MATRIX_ADMINS", "").split(",") if a.strip()}

PREFIXES = ("usr_", "pos_", "msg_")

client: AsyncClient


def log(message: str) -> None:
    print(message, flush=True)


def lookup(text: str) -> str | None:
    """Build a reply for a public ID (usr_/pos_/msg_). Runs in a worker thread."""
    db = SessionLocal()
    try:
        if text.startswith("usr_"):
            user = db.query(User).filter(User.public_id == text).first()
            if not user:
                return "❌ User not found."
            return (
                f"👤 USER DETAILS ({user.public_id})\n"
                f"• Username: @{user.username}\n"
                f"• Email: {user.email} ({'VERIFIED' if user.is_email_verified else 'UNVERIFIED'})\n"
                f"• Role: {user.system_role} | Badge: {user.experience_badge}\n"
                f"• Karma: {user.karma}\n"
                f"• Bio: {user.bio or 'None'}"
            )

        if text.startswith("pos_"):
            thread = db.query(ForumThread).filter(ForumThread.public_id == text).first()
            if not thread:
                return "❌ Thread not found."
            return (
                f"📌 THREAD DETAILS ({thread.public_id})\n"
                f"• Title: {thread.title}\n"
                f"• Author: @{thread.author.username} ({thread.author.public_id})\n"
                f"• Status: {thread.status} | Score: {thread.score}\n"
                f"• URL: https://askpc.cc/forum/thread/{thread.slug}\n\n"
                f"Content:\n{thread.content[:800]}"
            )

        if text.startswith("msg_"):
            reply = db.query(ForumReply).filter(ForumReply.public_id == text).first()
            if not reply:
                return "❌ Reply not found."
            return (
                f"💬 REPLY DETAILS ({reply.public_id})\n"
                f"• Author: @{reply.author.username} ({reply.author.public_id})\n"
                f"• Thread: {reply.thread.title} ({reply.thread.public_id})\n"
                f"• Score: {reply.score}\n\n"
                f"Content:\n{reply.content[:800]}"
            )

        return None
    finally:
        db.close()


async def send(room: MatrixRoom, body: str) -> None:
    await client.room_send(
        room.room_id, "m.room.message", {"msgtype": "m.text", "body": body}
    )


async def on_message(room: MatrixRoom, event: RoomMessageText) -> None:
    if event.sender == BOT_USER or event.sender not in ADMINS:
        return

    text = event.body.strip()
    if not text.startswith(PREFIXES):
        return

    try:
        answer = await asyncio.to_thread(lookup, text)
    except Exception as exc:  # keep the bot alive on DB errors
        log(f"lookup failed for {text!r}: {exc!r}")
        answer = "⚠️ Lookup failed, see bot logs."

    if answer:
        await send(room, answer)


async def on_invite(room: MatrixRoom, event: InviteMemberEvent) -> None:
    log(f"invite: room={room.room_id} sender={event.sender} target={event.state_key} membership={event.membership}")
    # Join only when an admin invites the bot.
    if (
        event.membership == "invite"
        and event.state_key == BOT_USER
        and event.sender in ADMINS
    ):
        result = await client.join(room.room_id)
        log(f"join {room.room_id}: {type(result).__name__}")

async def main() -> None:
    global client

    if not (BOT_USER and BOT_PASS):
        log("⚠️ MATRIX_BOT_USER or MATRIX_BOT_PASSWORD not set. Bot in standby mode.")
        return
    if not ADMINS:
        log("⚠️ MATRIX_ADMINS is empty: the bot will ignore every command.")
        log(f"admins: {sorted(ADMINS)}")

    client = AsyncClient(HOMESERVER, BOT_USER)
    try:
        resp = await client.login(BOT_PASS)
        if isinstance(resp, LoginError):
            log(f"❌ Login failed: {resp!r}")
            sys.exit(1)
        log(f"🤖 Matrix Moderation Bot connected as {client.user_id}!")

        # Pending invites are handled during the first sync.
        client.add_event_callback(on_invite, InviteMemberEvent)

        # First sync skips old history, so the bot doesn't answer old messages.
        first = await client.sync(timeout=10000, full_state=True)
        if isinstance(first, SyncError):
            log(f"❌ First sync failed: {first!r}")
            sys.exit(1)

        client.add_event_callback(on_message, RoomMessageText)
        await client.sync_forever(timeout=30000)
    finally:
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
