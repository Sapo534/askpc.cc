import os
import asyncio
from nio import AsyncClient, MatrixRoom, RoomMessageText
from app.database import SessionLocal
from app.models import User, ForumThread, ForumReply

HOMESERVER = os.getenv("MATRIX_HOMESERVER", "https://matrix.askpc.cc")
BOT_USER = os.getenv("MATRIX_BOT_USER", "")
BOT_PASS = os.getenv("MATRIX_BOT_PASSWORD", "")

async def message_callback(room: MatrixRoom, event: RoomMessageText) -> None:
    if event.sender == BOT_USER:
        return

    text = event.body.strip()
    db = SessionLocal()

    try:
        # Search User ID
        if text.startswith("usr_"):
            user = db.query(User).filter(User.public_id == text).first()
            if not user:
                await client.room_send(room.room_id, "m.room.message", {"msgtype": "m.text", "body": "❌ User not found."})
                return

            msg = (
                f"👤 USER DETAILS ({user.public_id})\n"
                f"• Username: @{user.username}\n"
                f"• Email: {user.email} ({'VERIFIED' if user.is_email_verified else 'UNVERIFIED'})\n"
                f"• Role: {user.system_role} | Badge: {user.experience_badge}\n"
                f"• Karma: {user.karma}\n"
                f"• Bio: {user.bio or 'None'}"
            )
            await client.room_send(room.room_id, "m.room.message", {"msgtype": "m.text", "body": msg})

        # Search Thread ID
        elif text.startswith("pos_"):
            thread = db.query(ForumThread).filter(ForumThread.public_id == text).first()
            if not thread:
                await client.room_send(room.room_id, "m.room.message", {"msgtype": "m.text", "body": "❌ Thread not found."})
                return

            msg = (
                f"📌 THREAD DETAILS ({thread.public_id})\n"
                f"• Title: {thread.title}\n"
                f"• Author: @{thread.author.username} ({thread.author.public_id})\n"
                f"• Status: {thread.status} | Score: {thread.score}\n"
                f"• URL: https://askpc.cc/forum/thread/{thread.slug}\n\n"
                f"Content:\n{thread.content[:800]}"
            )
            await client.room_send(room.room_id, "m.room.message", {"msgtype": "m.text", "body": msg})

        # Search Reply ID
        elif text.startswith("msg_"):
            reply = db.query(ForumReply).filter(ForumReply.public_id == text).first()
            if not reply:
                await client.room_send(room.room_id, "m.room.message", {"msgtype": "m.text", "body": "❌ Reply not found."})
                return

            msg = (
                f"💬 REPLY DETAILS ({reply.public_id})\n"
                f"• Author: @{reply.author.username} ({reply.author.public_id})\n"
                f"• Thread: {reply.thread.title} ({reply.thread.public_id})\n"
                f"• Score: {reply.score}\n\n"
                f"Content:\n{reply.content[:800]}"
            )
            await client.room_send(room.room_id, "m.room.message", {"msgtype": "m.text", "body": msg})

    finally:
        db.close()

async def main():
    global client
    client = AsyncClient(HOMESERVER, BOT_USER)
    client.add_event_callback(message_callback, RoomMessageText)

    if BOT_USER and BOT_PASS:
        await client.login(BOT_PASS)
        print(f"🤖 Matrix Moderation Bot connected as {BOT_USER}!")
        await client.sync_forever(timeout=30000)
    else:
        print("⚠️ MATRIX_BOT_USER or MATRIX_BOT_PASSWORD not set. Bot in standby mode.")

if __name__ == "__main__":
    asyncio.run(main())
