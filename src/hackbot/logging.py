"""Structured logging with redaction at the output boundary."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import logging
import os
import re
import sys
from typing import Mapping, TextIO
from urllib.parse import parse_qsl, urlsplit


REDACTED = "[REDACTED]"

_HEADER = re.compile(
    r"(?im)(?P<prefix>\b(?:authorization|proxy-authorization|cookie|set-cookie|"
    r"x-api-key|api-key)\s*:\s*)[^\r\n]+"
)
_AUTH_INLINE = re.compile(
    r"(?i)(?P<prefix>\b(?:authorization|proxy-authorization)\s*=\s*)[^\r\n,&;}]+"
)
_ASSIGNMENT = re.compile(
    r"(?P<name>\"[^\"]+\"|'[^']+'|[A-Za-z_][A-Za-z0-9_.-]*)"
    r"(?P<separator>\s*[:=]\s*)"
    r"(?P<value>\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^\s&,;}]+)"
)
_BEARER = re.compile(
    r"(?i)\bBearer[ \t]+(?!\[REDACTED\])"
    r"(?:\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^\s,;\]}'\"]+)"
)
_URL = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s<>\"']+")
_SENSITIVE_PARTS = (
    "password", "passwd", "pwd", "cookie", "authorization", "apikey",
    "accesskey", "privatekey", "secret", "credential", "session", "token",
    "databaseurl", "dburl", "connectionstring", "dsn",
)
_SENSITIVE_WORD = re.compile(r"(?:^|[^a-z0-9])(?:pass|pat|key|auth)(?:$|[^a-z0-9])", re.I)


def is_sensitive_key(key: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", key.lower())
    return any(part in normalized for part in _SENSITIVE_PARTS) or bool(_SENSITIVE_WORD.search(key))


@dataclass(frozen=True)
class SecretRedactor:
    known_values: tuple[str, ...] = ()

    @classmethod
    def from_environment(
        cls,
        environ: Mapping[str, str] | None = None,
        *,
        additional_values: tuple[str, ...] = (),
    ) -> SecretRedactor:
        env = os.environ if environ is None else environ
        values = {value for key, value in env.items() if is_sensitive_key(key) and value}
        values.update(value for value in additional_values if value)
        return cls(tuple(sorted(values, key=len, reverse=True)))

    def text(self, value: str) -> str:
        for secret in self.known_values:
            value = value.replace(secret, REDACTED)

        def replace_url(match: re.Match[str]) -> str:
            raw = match.group(0)
            try:
                parsed = urlsplit(raw)
                has_userinfo = "@" in parsed.netloc
                has_secret_query = any(is_sensitive_key(key) for key, _ in parse_qsl(
                    parsed.query, keep_blank_values=True
                ))
                has_secret_fragment = any(is_sensitive_key(key) for key, _ in parse_qsl(
                    parsed.fragment, keep_blank_values=True
                ))
            except ValueError:
                return REDACTED
            return REDACTED if has_userinfo or has_secret_query or has_secret_fragment else raw

        value = _URL.sub(replace_url, value)
        value = _HEADER.sub(lambda match: match.group("prefix") + REDACTED, value)
        value = _AUTH_INLINE.sub(lambda match: match.group("prefix") + REDACTED, value)
        value = _BEARER.sub("Bearer " + REDACTED, value)

        def replace_assignment(match: re.Match[str]) -> str:
            if is_sensitive_key(match.group("name")):
                return match.group("name") + match.group("separator") + REDACTED
            return match.group(0)

        return _ASSIGNMENT.sub(replace_assignment, value)

    def data(self, value: object) -> object:
        if isinstance(value, Mapping):
            return {
                self.text(str(key)): REDACTED if is_sensitive_key(str(key)) else self.data(item)
                for key, item in value.items()
            }
        if isinstance(value, (list, tuple, set)):
            return [self.data(item) for item in value]
        if isinstance(value, str):
            return self.text(value)
        if value is None or isinstance(value, (bool, int, float)):
            return value
        return self.text(str(value))


class JsonRedactingFormatter(logging.Formatter):
    def __init__(self, redactor: SecretRedactor) -> None:
        super().__init__()
        self._redactor = redactor

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "timestamp": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": self._redactor.text(record.name),
            "message": self._redactor.text(record.getMessage()),
        }
        context = getattr(record, "context", None)
        if context is not None:
            payload["context"] = self._redactor.data(context)
        if record.exc_info:
            payload["exception_type"] = record.exc_info[0].__name__
        return json.dumps(payload, sort_keys=True, ensure_ascii=True)


def create_logger(
    *,
    level: str = "INFO",
    stream: TextIO | None = None,
    environ: Mapping[str, str] | None = None,
    additional_secret_values: tuple[str, ...] = (),
) -> logging.Logger:
    """Create an independent logger; only whitelisted, redacted fields reach output."""

    if level.upper() not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
        raise ValueError("Unsupported logging level")
    logger = logging.Logger("hackbot", level=getattr(logging, level.upper()))
    handler = logging.StreamHandler(sys.stderr if stream is None else stream)
    handler.setFormatter(
        JsonRedactingFormatter(
            SecretRedactor.from_environment(environ, additional_values=additional_secret_values)
        )
    )
    logger.addHandler(handler)
    logger.propagate = False
    return logger
