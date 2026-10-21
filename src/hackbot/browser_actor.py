"""Keep the synchronous Playwright driver on one owning thread."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Lock, get_ident
from typing import Any, Callable

from .browser import (BrowserError, BrowserProxyConfig, IdentityObservation,
                      IdentityVerificationRule)
from .browser_playwright import BrowserNavigationObservation, PlaywrightBrowserDriver
from .domxss_browser import DOMBrowserObservation
from .postmessage_browser import (MessageBrowserObservation, MessageExperimentBinding,
                                  MessageVariant)
from .secrets import SecretValue


class PlaywrightBrowserActor:
    """Serialize browser operations; Playwright's sync greenlet is thread-affine."""

    name = "PLAYWRIGHT"

    def __init__(self, executable_path: Path | None = None) -> None:
        self._executable_path = executable_path
        self._worker = ThreadPoolExecutor(max_workers=1, thread_name_prefix="hackbot-browser")
        self._driver: PlaywrightBrowserDriver | None = None
        self._owner_thread: int | None = None
        self._running_lock = Lock()
        self._running: set[str] = set()

    def _on_owner(self, method: str, args: tuple[object, ...], kwargs: dict[str, object]) -> Any:
        if self._driver is None:
            self._owner_thread = get_ident()
            self._driver = PlaywrightBrowserDriver(self._executable_path)
        return getattr(self._driver, method)(*args, **kwargs)

    def _call(self, method: str, *args: object, **kwargs: object) -> Any:
        if get_ident() == self._owner_thread:
            return self._on_owner(method, args, kwargs)
        return self._worker.submit(self._on_owner, method, args, kwargs).result()

    def start(self, session_id: str, profile: Path, *, display: str | None,
              proxy: BrowserProxyConfig) -> None:
        self._call("start", session_id, profile, display=display, proxy=proxy)
        with self._running_lock:
            self._running.add(session_id)

    def stop(self, session_id: str) -> None:
        try:
            self._call("stop", session_id)
        finally:
            with self._running_lock:
                self._running.discard(session_id)

    def is_running(self, session_id: str) -> bool:
        with self._running_lock:
            return session_id in self._running

    def cookie_header_for(self, session_id: str, url: str) -> SecretValue:
        return self._call("cookie_header_for", session_id, url)

    def active_session_count(self) -> int:
        return int(self._call("active_session_count"))

    def close(self) -> None:
        if self.active_session_count():
            raise BrowserError("Running browser sessions must be stopped first")
        self._worker.shutdown(wait=True)

    def apply_imported_session(self, session_id: str, material: SecretValue,
                               allowed_url: Callable[[str], bool]) -> None:
        self._call("apply_imported_session", session_id, material, allowed_url)

    def observe_identity(self, session_id: str,
                         rule: IdentityVerificationRule) -> IdentityObservation:
        return self._call("observe_identity", session_id, rule)

    def observe_current_page(self, session_id: str) -> dict[str, object] | None:
        return self._call("observe_current_page", session_id)

    def navigate_readonly(self, session_id: str, url: str,
                          gate: Callable[[str, str, bool], object],
                          redirect_allowed: Callable[[str], bool], *,
                          request_cap: int = 24, timeout_ms: int = 20000,
                          response_cap: int = 2_097_152) -> BrowserNavigationObservation:
        return self._call("navigate_readonly", session_id, url, gate, redirect_allowed,
                          request_cap=request_cap, timeout_ms=timeout_ms,
                          response_cap=response_cap)

    def execute_dom_variant(self, session_id: str, url: str, marker: str,
                            expected_asset_url: str,
                            gate: Callable[[str, str, bool], bool], *,
                            authenticated: bool, request_cap: int,
                            timeout_ms: int) -> DOMBrowserObservation:
        return self._call("execute_dom_variant", session_id, url, marker,
                          expected_asset_url, gate, authenticated=authenticated,
                          request_cap=request_cap, timeout_ms=timeout_ms)

    def execute_message_trial(self, session_id: str, binding: MessageExperimentBinding,
                              variant: MessageVariant,
                              gate: Callable[[str, str, bool], str | bool | None], *,
                              authenticated: bool, request_cap: int,
                              timeout_ms: int) -> MessageBrowserObservation:
        return self._call("execute_message_trial", session_id, binding, variant, gate,
                          authenticated=authenticated, request_cap=request_cap,
                          timeout_ms=timeout_ms)
