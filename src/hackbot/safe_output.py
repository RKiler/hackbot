"""Conservative text boundary for notification and report metadata."""

from __future__ import annotations

import html
import re

from .logging import SecretRedactor


_EMAIL = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
_PHONE = re.compile(r"(?<![\w])(?:\+?\d[\d\s().-]{8,}\d)(?![\w])")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_LONG_HEX = re.compile(r"\b[0-9a-fA-F]{32,}\b")
_LONG_BASE64 = re.compile(r"\b[A-Za-z0-9_/-]{48,}={0,2}\b")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_WHITESPACE = re.compile(r"\s+")
_MARKDOWN = re.compile(r"([\\`*_{}\[\]()#+.!|<>])")


def safe_text(value: object, *, limit: int = 240, markdown: bool = False) -> str:
    """Minimize untrusted prose; evidence bodies must never be passed here."""
    if not isinstance(value, str) or not 1 <= limit <= 4096:
        return "[not available]"
    text = SecretRedactor.from_environment().text(value)
    text = _JWT.sub("[REDACTED_TOKEN]", text)
    text = _EMAIL.sub("[REDACTED_EMAIL]", text)
    text = _PHONE.sub("[REDACTED_PHONE]", text)
    text = _LONG_HEX.sub("[REDACTED_VALUE]", text)
    text = _LONG_BASE64.sub("[REDACTED_VALUE]", text)
    text = _WHITESPACE.sub(" ", _CONTROL.sub("", text)).strip()
    text = text[:limit].strip() or "[not available]"
    return _MARKDOWN.sub(r"\\\1", text) if markdown else text


def safe_html(value: object, *, limit: int = 4096) -> str:
    return html.escape(safe_text(value, limit=limit), quote=True)
