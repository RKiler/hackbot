"""Optional Playwright execution boundary for BugHunter-owned browser profiles."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

from .browser import (BrowserError, BrowserProxyConfig, IdentityObservation,
                      IdentityVerificationRule)
from .secrets import SecretValue


class PlaywrightBrowserDriver:
    """In-process persistent Chromium contexts; never attaches to recon CDP."""

    name = "PLAYWRIGHT"

    def __init__(self, executable_path: Path | None = None) -> None:
        if executable_path is not None and (not isinstance(executable_path, Path)
                                            or not executable_path.is_absolute()):
            raise BrowserError("Invalid Chromium executable path")
        self._executable_path = executable_path
        self._playwright = None
        self._contexts: dict[str, object] = {}

    def start(self, session_id: str, profile: Path, *, display: str | None,
              proxy: BrowserProxyConfig) -> None:
        if session_id in self._contexts:
            raise BrowserError("Browser session is already running")
        if proxy.ca_reference is not None:
            raise BrowserError("Custom proxy CA is deferred; no trust override was applied")
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            raise BrowserError("Install the browser extra to use Playwright") from None
        if self._playwright is None:
            self._playwright = sync_playwright().start()
        browser_env = {"PATH": "/usr/bin:/bin", "HOME": str(profile.parent),
                       "LANG": os.environ.get("LANG", "C.UTF-8")}
        options = {"headless": display is None, "chromium_sandbox": False,
                   "ignore_https_errors": False, "accept_downloads": False,
                   "env": browser_env}
        if display is not None:
            browser_env["DISPLAY"] = display
            if os.environ.get("XAUTHORITY"):
                browser_env["XAUTHORITY"] = os.environ["XAUTHORITY"]
        if proxy.enabled:
            assert proxy.proxy_url is not None
            options["proxy"] = {"server": proxy.proxy_url}
        if self._executable_path is not None:
            if not self._executable_path.is_file():
                raise BrowserError("Configured Chromium executable is unavailable")
            options["executable_path"] = str(self._executable_path)
        try:
            context = self._playwright.chromium.launch_persistent_context(str(profile), **options)
        except Exception:
            raise BrowserError("Chromium launch failed") from None
        self._contexts[session_id] = context

    def stop(self, session_id: str) -> None:
        context = self._contexts.pop(session_id, None)
        if context is not None:
            try:
                context.close()
            except Exception:
                raise BrowserError("Chromium close failed") from None
        if not self._contexts and self._playwright is not None:
            self._playwright.stop()
            self._playwright = None

    def is_running(self, session_id: str) -> bool:
        return session_id in self._contexts

    def apply_imported_session(self, session_id: str, material: SecretValue,
                               allowed_url: Callable[[str], bool]) -> None:
        context = self._contexts.get(session_id)
        if context is None:
            raise BrowserError("Browser is not running")
        raw = material.reveal(execution_boundary=True)
        if len(raw) > 65536:
            raise BrowserError("Imported session is too large")
        try:
            data = json.loads(raw)
            if not isinstance(data, dict) or set(data) != {"format", "cookies"} or data["format"] != "hackbot-cookie-v1":
                raise ValueError
            items = data["cookies"]
            if not isinstance(items, list) or not 1 <= len(items) <= 64:
                raise ValueError
            cookies = []
            for item in items:
                if not isinstance(item, dict) or set(item) != {"url", "name", "value"}:
                    raise ValueError
                url, name, value = item["url"], item["name"], item["value"]
                if not all(isinstance(v, str) for v in (url, name, value)) or not name or not value:
                    raise ValueError
                parsed = urlsplit(url)
                if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
                        or parsed.path not in {"", "/"} or parsed.query or parsed.fragment
                        or not allowed_url(url)):
                    raise ValueError
                cookies.append({"url": url, "name": name, "value": value})
            try:
                context.add_cookies(cookies)
            except Exception:
                context.clear_cookies()
                raise
        except Exception:
            raise BrowserError("Imported session is invalid or outside authorized scope") from None

    def observe_identity(self, session_id: str, rule: IdentityVerificationRule) -> IdentityObservation:
        context = self._contexts.get(session_id)
        if context is None or not context.pages:
            return IdentityObservation()
        page = context.pages[-1]

        def read(selector: str | None) -> str | None:
            if selector is None:
                return None
            try:
                value = page.locator(selector).first.text_content(timeout=1500)
            except Exception:
                return None
            return value.strip() if value and value.strip() else None

        return IdentityObservation(
            user_id=read(rule.user_id_selector), email=read(rule.email_selector),
            tenant_id=read(rule.tenant_selector),
        )
