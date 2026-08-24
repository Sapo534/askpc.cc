import secrets
from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Boolean, UniqueConstraint
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

def gen_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(4)}"

class Tag(Base):
    __tablename__ = "tags"
    id = Column(Integer, primary_key=True)
    name = Column(String(50), unique=True, index=True, nullable=False)

class ArticleTag(Base):
    __tablename__ = "article_tags"
    article_id = Column(Integer, ForeignKey("articles.id"), primary_key=True)
    tag_id = Column(Integer, ForeignKey("tags.id"), primary_key=True)

class ThreadTag(Base):
    __tablename__ = "thread_tags"
    thread_id = Column(Integer, ForeignKey("forum_threads.id"), primary_key=True)
    tag_id = Column(Integer, ForeignKey("tags.id"), primary_key=True)

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    public_id = Column(String(20), unique=True, index=True, default=lambda: gen_id("usr"))
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=True)
    avatar_url = Column(String(255), default="/static/default-avatar.png")
    
    experience_badge = Column(String(20), default="Teapot")
    system_role = Column(String(20), default="user")
    is_sponsor = Column(Boolean, default=False)
    custom_color = Column(String(10), nullable=True)
    karma = Column(Integer, default=0)
    bio = Column(Text, nullable=True)
    
    is_email_verified = Column(Boolean, default=False)
    email_verification_token = Column(String(100), nullable=True)
    reset_password_token = Column(String(100), nullable=True)
    reset_password_expiry = Column(DateTime, nullable=True)
    last_username_change = Column(DateTime, nullable=True)
    last_email_change = Column(DateTime, nullable=True)
    last_password_change = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)

class Article(Base):
    __tablename__ = "articles"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    slug = Column(String(255), unique=True, index=True, nullable=False)
    file_path = Column(String(255), unique=True, index=True, nullable=True)
    category = Column(String(50), index=True, default="General")
    difficulty = Column(String(20), default="Beginner")
    license = Column(String(50), default="CC-BY-SA-4.0")
    content_markdown = Column(Text, nullable=False)
    author_id = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    author = relationship("User")
    tags = relationship("Tag", secondary="article_tags")

class ForumThread(Base):
    __tablename__ = "forum_threads"

    id = Column(Integer, primary_key=True, index=True)
    public_id = Column(String(20), unique=True, index=True, default=lambda: gen_id("pos"))
    title = Column(String(255), nullable=False)
    slug = Column(String(255), unique=True, index=True, nullable=False)
    content = Column(Text, nullable=False)
    status = Column(String(10), default="OPEN")
    score = Column(Integer, default=0)
    
    attachment_url = Column(String(255), nullable=True)
    attachment_name = Column(String(255), nullable=True)

    author_id = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, default=datetime.utcnow)

    author = relationship("User")
    replies = relationship("ForumReply", back_populates="thread")
    tags = relationship("Tag", secondary="thread_tags")

class ForumReply(Base):
    __tablename__ = "forum_replies"

    id = Column(Integer, primary_key=True, index=True)
    public_id = Column(String(20), unique=True, index=True, default=lambda: gen_id("msg"))
    thread_id = Column(Integer, ForeignKey("forum_threads.id"))
    author_id = Column(Integer, ForeignKey("users.id"))
    content = Column(Text, nullable=False)
    score = Column(Integer, default=0)

    attachment_url = Column(String(255), nullable=True)
    attachment_name = Column(String(255), nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)

    thread = relationship("ForumThread", back_populates="replies")
    author = relationship("User")

class ThreadVote(Base):
    __tablename__ = "thread_votes"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    thread_id = Column(Integer, ForeignKey("forum_threads.id"), nullable=False)
    value = Column(Integer, nullable=False)
    __table_args__ = (UniqueConstraint('user_id', 'thread_id', name='unique_user_thread_vote'),)

class ReplyVote(Base):
    __tablename__ = "reply_votes"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    reply_id = Column(Integer, ForeignKey("forum_replies.id"), nullable=False)
    value = Column(Integer, nullable=False)
    __table_args__ = (UniqueConstraint('user_id', 'reply_id', name='unique_user_reply_vote'),)
