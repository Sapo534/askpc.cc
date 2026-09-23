"""Secure upload saver: extension allow-list, 5MB cap, magic bytes, Pillow check."""
import os
import secrets
import shutil
from typing import Optional, Tuple

from fastapi import UploadFile
from PIL import Image

ALLOWED_ATTACHMENTS = {
    ".png", ".jpg", ".jpeg", ".webp", ".gif", ".pdf",
    ".md", ".txt", ".log", ".py", ".sh", ".c", ".cpp",
    ".rs", ".zig", ".js", ".ts", ".json", ".conf",
}
IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp", ".gif"}
MAX_UPLOAD_BYTES = 5 * 1024 * 1024


def save_secure_file(
    upload_file: Optional[UploadFile], folder: str = "uploads"
) -> Tuple[Optional[str], Optional[str]]:
    if not upload_file or not upload_file.filename:
        return None, None

    ext = os.path.splitext(upload_file.filename)[1].lower()
    if ext not in ALLOWED_ATTACHMENTS:
        raise ValueError("Unsupported file type.")

    upload_file.file.seek(0, 2)
    file_size = upload_file.file.tell()
    upload_file.file.seek(0)
    if file_size > MAX_UPLOAD_BYTES:
        raise ValueError("File exceeds maximum 5MB size limit.")

    header = upload_file.file.read(10)
    upload_file.file.seek(0)
    if b"MZ" in header or b"ELF" in header or b"<?php" in header:
        raise ValueError("Security Violation: Executable binary payload detected.")

    if ext in IMAGE_EXTENSIONS:
        try:
            Image.open(upload_file.file).verify()
            upload_file.file.seek(0)
        except Exception:
            raise ValueError("Corrupted or invalid image file.")

    filename = f"{secrets.token_hex(10)}{ext}"
    with open(f"app/static/{folder}/{filename}", "wb") as buffer:
        shutil.copyfileobj(upload_file.file, buffer)

    return f"/static/{folder}/{filename}", upload_file.filename
