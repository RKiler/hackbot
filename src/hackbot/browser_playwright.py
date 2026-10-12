"""Optional Playwright execution boundary for BugHunter-owned browser profiles."""

from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
from typing import Callable
from urllib.parse import urljoin, urlsplit
import uuid

from .browser import (BrowserError, BrowserProxyConfig, IdentityObservation,
                      IdentityVerificationRule)
from .browser_trust import ProfileTrustError, install_profile_ca
from .domxss_browser import DOMBrowserObservation
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
        self._proxy_settings: dict[str, BrowserProxyConfig] = {}

    def start(self, session_id: str, profile: Path, *, display: str | None,
              proxy: BrowserProxyConfig) -> None:
        if session_id in self._contexts:
            raise BrowserError("Browser session is already running")
        if proxy.ca_reference is not None and proxy.ca_certificate is None:
            raise BrowserError("Profile CA certificate is required")
        if proxy.ca_certificate is not None:
            try:
                install_profile_ca(profile, proxy.ca_certificate)
            except ProfileTrustError:
                raise BrowserError("Profile-only CA trust could not be configured") from None
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
            if proxy.capture_required:
                options["args"] = ["--proxy-bypass-list=<-loopback>"]
        if self._executable_path is not None:
            if not self._executable_path.is_file():
                raise BrowserError("Configured Chromium executable is unavailable")
            options["executable_path"] = str(self._executable_path)
        try:
            context = self._playwright.chromium.launch_persistent_context(str(profile), **options)
        except Exception:
            raise BrowserError("Chromium launch failed") from None
        self._contexts[session_id] = context
        self._proxy_settings[session_id] = proxy

    def stop(self, session_id: str) -> None:
        context = self._contexts.pop(session_id, None)
        self._proxy_settings.pop(session_id, None)
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

    def execute_dom_variant(self, session_id: str, url: str, marker: str,
                            expected_asset_url: str,
                            gate: Callable[[str, str, bool], bool], *,
                            authenticated: bool, request_cap: int,
                            timeout_ms: int) -> DOMBrowserObservation:
        """Fresh isolated browser; all network requests pass the supplied policy gate."""
        source = self._contexts.get(session_id)
        proxy = self._proxy_settings.get(session_id)
        if source is None or proxy is None or self._playwright is None:
            raise BrowserError("Verified browser session is not running")
        if proxy.capture_required and proxy.ca_certificate is not None:
            raise BrowserError("Fresh-context proxy trust is not configured")
        if not 1 <= request_cap <= 48 or not 1000 <= timeout_ms <= 20000:
            raise BrowserError("DOM browser budget is invalid")
        options = {"headless": True, "chromium_sandbox": False}
        if self._executable_path is not None:
            options["executable_path"] = str(self._executable_path)
        if proxy.enabled:
            options["proxy"] = {"server": proxy.proxy_url}
        try:
            storage_state = source.storage_state() if authenticated else None
            browser = self._playwright.chromium.launch(**options)
        except Exception:
            raise BrowserError("Fresh DOM browser context could not start") from None
        context = None
        count = 0
        denied = 0
        blocked_by_browser = False
        response_status = None
        bundle_sha256 = None
        csp = None
        navigation_only = False
        context_id = "DOMCTX-" + uuid.uuid4().hex
        try:
            context = browser.new_context(
                storage_state=storage_state, accept_downloads=False,
                ignore_https_errors=False, service_workers="block",
            )

            def handle(route) -> None:
                nonlocal count, denied, bundle_sha256
                request = route.request
                count += 1
                if count > request_cap or not gate(request.url, request.method,
                                                    request.is_navigation_request()):
                    denied += 1
                    route.abort()
                    return
                try:
                    response = route.fetch(max_redirects=0, timeout=min(timeout_ms, 5000))
                    if response.status in {301, 302, 303, 307, 308}:
                        destination = response.headers.get("location")
                        if not destination or not gate(urljoin(request.url, destination), "GET", True):
                            denied += 1
                            route.abort()
                            return
                    if int(response.headers.get("content-length", "0")) > 2_097_152:
                        denied += 1
                        route.abort()
                        return
                    if request.url == expected_asset_url and response.status == 200:
                        body = response.body()
                        if len(body) > 1_048_576:
                            denied += 1
                            route.abort()
                            return
                        bundle_sha256 = hashlib.sha256(body).hexdigest()
                    route.fulfill(response=response)
                except Exception:
                    denied += 1
                    try:
                        route.abort()
                    except Exception:
                        pass

            context.route("**/*", handle)
            page = context.new_page()

            def console_error(message) -> None:
                nonlocal blocked_by_browser
                if message.type == "error" and (
                        "content security policy" in message.text.lower() or
                        "trusted types" in message.text.lower()):
                    blocked_by_browser = True

            page.on("console", console_error)
            error_code = None
            try:
                response = page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
                response_status = response.status if response else None
                csp = response.headers.get("content-security-policy") if response else None
                page.wait_for_timeout(600)
            except Exception:
                error_code = "BROWSER_NAVIGATION_FAILED"
            marker_context = None
            document_origin = None
            for index, frame in enumerate(page.frames[:16]):
                try:
                    value = frame.locator("html").get_attribute("data-hackbot-dom-proof", timeout=500)
                except Exception:
                    continue
                if value == marker:
                    marker_context = "MAIN" if index == 0 else "IFRAME"
                    parsed = urlsplit(frame.url)
                    if parsed.scheme in {"http", "https"} and parsed.hostname:
                        document_origin = f"{parsed.scheme}://{parsed.netloc}"
                    elif index > 0 and frame.url == "about:blank":
                        try:
                            sandbox = frame.frame_element().get_attribute("sandbox")
                        except Exception:
                            sandbox = ""
                        if sandbox is None or "allow-same-origin" in sandbox.split():
                            parent = urlsplit(page.url)
                            if parent.scheme in {"http", "https"} and parent.hostname:
                                document_origin = f"{parent.scheme}://{parent.netloc}"
                    break
            sandboxes = []
            try:
                for iframe in page.locator("iframe").all()[:8]:
                    value = iframe.get_attribute("sandbox", timeout=500)
                    if value is not None:
                        sandboxes.append(value[:120])
            except Exception:
                pass
            try:
                before, after = urlsplit(url), urlsplit(page.url)
                navigation_only = (marker_context is None and
                                   (before.netloc, before.path) != (after.netloc, after.path))
            except ValueError:
                pass
            return DOMBrowserObservation(
                context_id=context_id, marker_observed=marker_context is not None,
                marker_context=marker_context, document_origin=document_origin,
                response_status=response_status, bundle_sha256=bundle_sha256,
                csp_present=bool(csp),
                trusted_types_enforced=bool(csp and "require-trusted-types-for" in csp.lower()),
                sandbox_flags=tuple(sandboxes), browser_blocked=blocked_by_browser,
                navigation_only=navigation_only, request_count=count,
                denial_count=denied, error_code=error_code,
            )
        finally:
            if context is not None:
                try:
                    context.close()
                except Exception:
                    pass
            browser.close()
