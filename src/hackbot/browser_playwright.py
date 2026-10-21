"""Optional Playwright execution boundary for BugHunter-owned browser profiles."""

from __future__ import annotations

import json
import hashlib
import os
from dataclasses import dataclass, field, replace
from pathlib import Path
import re
import time
from typing import Callable
from urllib.parse import urljoin, urlsplit
import uuid

from .browser import (BrowserError, BrowserProxyConfig, IdentityObservation,
                      IdentityVerificationRule)
from .browser_proxy_guard import BrowserProxyGuard, BrowserProxyGuardError
from .browser_trust import ProfileTrustError, install_profile_ca
from .domxss_browser import DOMBrowserObservation
from .logging import is_sensitive_key
from .postmessage_browser import (MessageBrowserObservation, MessageExperimentBinding,
                                  MessageVariant, lookalike_origin)
from .secrets import SecretValue
from .target_scope import ScopeResult


_COOKIE_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,256}\Z")


@dataclass(frozen=True, slots=True)
class BrowserNavigationObservation:
    url: str = field(repr=False)
    status_code: int | None
    scripts: tuple[str, ...] = field(repr=False)
    links: tuple[str, ...] = field(repr=False)
    forms: tuple[tuple[str, str], ...] = field(repr=False)
    buttons: tuple[tuple[str, str], ...] = field(repr=False)
    request_count: int
    denied_count: int
    redirect_count: int
    error_code: str | None
    form_fields: tuple[tuple[tuple[str, str], ...], ...] = field(default=(), repr=False)


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
        self._proxy_guards: dict[str, BrowserProxyGuard] = {}
        self._mapping_active: set[str] = set()
        self._websocket_routed: set[str] = set()

    def start(self, session_id: str, profile: Path, *, display: str | None,
              proxy: BrowserProxyConfig) -> None:
        if session_id in self._contexts:
            raise BrowserError("Browser session is already running")
        if proxy.ca_reference is not None and proxy.ca_certificate is None:
            raise BrowserError("Profile CA certificate is required")
        if proxy.capture_required and proxy.guard_scope is None:
            raise BrowserError("Captured browser requires target-scoped transport guard")
        if proxy.ca_certificate is not None:
            try:
                install_profile_ca(profile, proxy.ca_certificate)
            except ProfileTrustError:
                raise BrowserError("Profile-only CA trust could not be configured") from None
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            raise BrowserError("Install the browser extra to use Playwright") from None
        guard = None
        if proxy.capture_required:
            try:
                assert proxy.proxy_url is not None and proxy.guard_scope is not None
                guard = BrowserProxyGuard(proxy.guard_scope, proxy.proxy_url)
            except BrowserProxyGuardError:
                raise BrowserError("Target-scoped browser transport is unavailable") from None
        try:
            if self._playwright is None:
                self._playwright = sync_playwright().start()
        except Exception:
            if guard is not None:
                guard.close()
            raise BrowserError("Playwright could not start") from None
        browser_env = {"PATH": "/usr/bin:/bin", "HOME": str(profile.parent),
                       "LANG": os.environ.get("LANG", "C.UTF-8")}
        options = {"headless": display is None, "chromium_sandbox": False,
                   "ignore_https_errors": False, "accept_downloads": False,
                   "service_workers": "block",
                   "args": ["--disable-background-networking", "--disable-component-update",
                            "--disable-domain-reliability", "--disable-sync",
                            "--metrics-recording-only", "--no-first-run"],
                   "env": browser_env}
        if display is not None:
            browser_env["DISPLAY"] = display
            if os.environ.get("XAUTHORITY"):
                browser_env["XAUTHORITY"] = os.environ["XAUTHORITY"]
        if proxy.enabled:
            assert proxy.proxy_url is not None
            options["proxy"] = {"server": guard.proxy_url if guard else proxy.proxy_url}
            if proxy.capture_required:
                options["args"].append("--proxy-bypass-list=<-loopback>")
        if self._executable_path is not None:
            if not self._executable_path.is_file():
                raise BrowserError("Configured Chromium executable is unavailable")
            options["executable_path"] = str(self._executable_path)
        try:
            context = self._playwright.chromium.launch_persistent_context(str(profile), **options)
        except Exception:
            if guard is not None:
                guard.close()
            raise BrowserError("Chromium launch failed") from None
        self._contexts[session_id] = context
        self._proxy_settings[session_id] = replace(proxy, proxy_url=guard.proxy_url) if guard else proxy
        if guard is not None:
            self._proxy_guards[session_id] = guard

    def stop(self, session_id: str) -> None:
        context = self._contexts.pop(session_id, None)
        self._proxy_settings.pop(session_id, None)
        guard = self._proxy_guards.pop(session_id, None)
        self._mapping_active.discard(session_id)
        self._websocket_routed.discard(session_id)
        if context is not None:
            try:
                context.close()
            except Exception:
                raise BrowserError("Chromium close failed") from None
            finally:
                if guard is not None:
                    guard.close()
        elif guard is not None:
            guard.close()
        if not self._contexts and self._playwright is not None:
            self._playwright.stop()
            self._playwright = None

    def is_running(self, session_id: str) -> bool:
        return session_id in self._contexts

    def cookie_header_for(self, session_id: str, url: str) -> SecretValue:
        """Return a current matching cookie header only at the trusted execution boundary."""
        context = self._contexts.get(session_id)
        proxy = self._proxy_settings.get(session_id)
        if context is None or proxy is None or not proxy.capture_required or proxy.guard_scope is None:
            raise BrowserError("Verified captured browser session is required")
        try:
            parsed = urlsplit(url)
            if (parsed.scheme not in {"http", "https"} or parsed.hostname is None
                    or parsed.username is not None or parsed.password is not None
                    or parsed.fragment or proxy.guard_scope.evaluate_url(url).result
                    is not ScopeResult.IN_SCOPE):
                raise ValueError
        except ValueError:
            raise BrowserError("Cookie destination is outside the captured scope") from None
        host = parsed.hostname.lower()
        path = parsed.path or "/"
        try:
            cookies = context.cookies(urls=[url])
        except Exception:
            raise BrowserError("Browser cookies are unavailable") from None
        selected = []
        for cookie in cookies:
            name, value = cookie.get("name"), cookie.get("value")
            domain, cookie_path = cookie.get("domain"), cookie.get("path")
            if (not isinstance(domain, str) or not isinstance(cookie_path, str)
                    or not isinstance(name, str) or not isinstance(value, str)
                    or not _COOKIE_NAME.fullmatch(name)
                    or any(ord(char) < 33 or ord(char) > 126 or char in ";\\" for char in value)):
                raise BrowserError("Browser cookie cannot be used safely")
            domain = domain.lower()
            if domain.startswith("."):
                if host != domain[1:] and not host.endswith(domain):
                    continue
            elif host != domain:
                continue
            if (not cookie_path.startswith("/") or not path.startswith(cookie_path)
                    or (len(path) > len(cookie_path) and not cookie_path.endswith("/")
                        and path[len(cookie_path)] != "/")):
                continue
            if cookie.get("secure") and parsed.scheme != "https":
                continue
            expires = cookie.get("expires")
            if isinstance(expires, (int, float)) and expires >= 0 and expires <= time.time():
                continue
            selected.append(f"{name}={value}")
        header = "; ".join(selected)
        if not header or len(header) > 8192:
            raise BrowserError("No usable browser cookie is available")
        return SecretValue(header)

    def active_session_count(self) -> int:
        return len(self._contexts)

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

    def observe_current_page(self, session_id: str) -> dict[str, object] | None:
        """Read bounded DOM metadata from an already open page; never navigate or evaluate JS."""
        context = self._contexts.get(session_id)
        if context is None or not context.pages:
            return None
        page = context.pages[-1]
        try:
            scripts = tuple((item.get_attribute("src", timeout=500) or "")
                            for item in page.locator("script[src]").all()[:20])
            links = tuple((item.get_attribute("href", timeout=500) or "")
                          for item in page.locator("a[href]").all()[:20])
            forms = tuple((item.get_attribute("action", timeout=500) or "")
                          for item in page.locator("form[action]").all()[:10])
            return {"url": page.url, "title_present": bool(page.title()),
                    "scripts": tuple(value for value in scripts if value),
                    "links": tuple(value for value in links if value),
                    "forms": tuple(value for value in forms if value)}
        except Exception:
            return None

    def navigate_readonly(self, session_id: str, url: str,
                          gate: Callable[[str, str, bool], object],
                          redirect_allowed: Callable[[str], bool], *,
                          request_cap: int = 24, timeout_ms: int = 20000,
                          response_cap: int = 2_097_152) -> BrowserNavigationObservation:
        """Inspect one page with every HTTP request intercepted and separately authorized."""
        context = self._contexts.get(session_id)
        proxy = self._proxy_settings.get(session_id)
        if context is None or proxy is None or not proxy.enabled or not proxy.capture_required:
            raise BrowserError("Captured browser session is required for mapping")
        if (session_id in self._mapping_active or not 1 <= request_cap <= 96
                or not 1000 <= timeout_ms <= 30000
                or not 65536 <= response_cap <= 2_097_152):
            raise BrowserError("Invalid or concurrent browser mapping request")
        if context.service_workers:
            raise BrowserError("Existing service workers prevent policy-gated mapping")
        parts = urlsplit(url)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            raise BrowserError("Invalid browser navigation URL")
        self._mapping_active.add(session_id)
        if session_id not in self._websocket_routed:
            context.route_web_socket("**/*", lambda ws: ws.close() if session_id in self._mapping_active
                                     else ws.connect())
            self._websocket_routed.add(session_id)
        page = None
        current_url = url
        redirect_to = None
        request_count = denied_count = redirect_count = 0
        status_code = None
        error_code = None
        route_failure = None

        def handle(route) -> None:
            nonlocal request_count, denied_count, redirect_to, status_code, route_failure
            request = route.request
            request_count += 1
            if (request_count > request_cap or request.method not in {"GET", "HEAD"}
                    or request.resource_type not in {
                        "document", "script", "stylesheet", "xhr", "fetch"}):
                denied_count += 1
                route.abort()
                return
            try:
                ticket = gate(request.url, request.method, request.is_navigation_request())
            except Exception:
                ticket = None
            if not ticket:
                denied_count += 1
                route.abort()
                return
            release = getattr(gate, "release", None)
            succeeded = False
            stage = "FETCH"
            try:
                response = route.fetch(max_redirects=0, timeout=min(timeout_ms, 10000))
                if 300 <= response.status < 400:
                    destination = response.headers.get("location")
                    if (request.resource_type == "document" and request.url == current_url
                            and destination):
                        redirect_to = urljoin(request.url, destination)
                    denied_count += 1
                    route.abort()
                    return
                length = response.headers.get("content-length", "0")
                if length.isdecimal() and int(length) > response_cap:
                    denied_count += 1
                    route.abort()
                    return
                body = response.body()
                if len(body) > response_cap:
                    denied_count += 1
                    route.abort()
                    return
                if request.resource_type == "document" and request.url == current_url:
                    status_code = response.status
                stage = "FULFILL"
                route.fulfill(response=response)
                succeeded = True
            except Exception:
                route_failure = "BROWSER_" + stage + "_FAILED"
                denied_count += 1
                try:
                    route.abort()
                except Exception:
                    pass
            finally:
                if callable(release):
                    release(ticket, succeeded)

        try:
            context.route("**/*", handle)
            for _ in range(5):
                if page is not None:
                    page.close()
                page = context.new_page()
                redirect_to = None
                try:
                    page.goto(current_url, wait_until="domcontentloaded", timeout=timeout_ms)
                except Exception:
                    if redirect_to is None:
                        error_code = route_failure or "NAVIGATION_FAILED"
                if redirect_to is None:
                    break
                redirect_count += 1
                if redirect_count > 4 or not redirect_allowed(redirect_to):
                    error_code = "REDIRECT_DENIED"
                    break
                current_url = redirect_to
            if error_code is None:
                page.wait_for_timeout(200)
            scripts = tuple((item.get_attribute("src", timeout=500) or "")
                            for item in page.locator("script[src]").all()[:24]) if error_code is None else ()
            links = tuple((item.get_attribute("href", timeout=500) or "")
                          for item in page.locator("a[href]").all()[:40]) if error_code is None else ()
            form_nodes = page.locator("form").all()[:16] if error_code is None else ()
            forms = tuple(((item.get_attribute("action", timeout=500) or ""),
                           (item.get_attribute("method", timeout=500) or "GET").upper())
                          for item in form_nodes)
            form_fields = []
            for form in form_nodes:
                fields = []
                for control in form.locator("input[name], select[name], textarea[name]").all()[:16]:
                    name = control.get_attribute("name", timeout=500) or ""
                    tag = control.evaluate("element => element.tagName.toLowerCase()")
                    kind = control.get_attribute("type", timeout=500) or (
                        "text" if tag == "input" else tag)
                    if (re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", name) and
                            not is_sensitive_key(name) and
                            kind in {"text", "search", "textarea", "select", "number", "checkbox"}):
                        fields.append((name, kind))
                form_fields.append(tuple(dict.fromkeys(fields)))
            buttons = tuple(((item.get_attribute("type", timeout=500) or "button"),
                             (item.get_attribute("aria-label", timeout=500) or "")[:80])
                            for item in page.locator("button").all()[:24]) if error_code is None else ()
            return BrowserNavigationObservation(
                current_url, status_code, tuple(item for item in scripts if item),
                tuple(item for item in links if item), forms, buttons,
                request_count, denied_count, redirect_count, error_code,
                tuple(form_fields))
        finally:
            try:
                if page is not None:
                    page.close()
            finally:
                try:
                    context.unroute("**/*", handle)
                finally:
                    self._mapping_active.discard(session_id)

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
                    if 300 <= response.status < 400:
                        # Fulfilled browser redirects bypass route interception on later hops.
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

    @staticmethod
    def _message_fixture(binding: MessageExperimentBinding, variant: MessageVariant,
                         marker: str | None = None,
                         context_id: str | None = None) -> bytes:
        """Generate a fixed local sender; observed strings are JSON-escaped, never executable code."""
        if (binding.window_mode not in {"IFRAME", "POPUP"}
                or not 1 <= len(binding.activation_type) <= 80
                or binding.port_type is not None and len(binding.port_type) > 80
                or binding.allowed_method not in {None, "ping", "getVersion", "getStatus",
                                               "readSynthetic", "readCanary"}
                or binding.owned_canary_value is not None and (
                    binding.allowed_method != "readCanary"
                    or not re.fullmatch(r"[a-z][a-z0-9-]{3,79}",
                                        binding.owned_canary_value))
                or binding.dom_field is not None and (
                    not re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]{0,63}", binding.dom_field)
                    or binding.dom_field in {"type", "event", "action", "kind", "method",
                                             "__proto__", "constructor", "prototype"})
                or binding.dom_field and not re.fullmatch(r"MSGDOM-[0-9a-f]{32}", marker or "")):
            raise BrowserError("Messaging fixture binding is invalid")
        safe = lambda value: json.dumps(value, ensure_ascii=True).replace("<", "\\u003c")
        activation = safe(binding.activation_type)
        port_type = safe(binding.port_type)
        method = safe(binding.allowed_method)
        dom_field = safe(binding.dom_field)
        proof_html = safe(
            "<img src=x onerror=\"document.documentElement.setAttribute("
            f"'data-hackbot-dom-proof','{marker}');"
            "(window.opener||window.parent).postMessage({"
            f"type:'HACKBOT_DOM_ORIGIN',marker:'{marker}'"
            "},'*')\">" if marker else "")
        victim = safe(binding.route_url)
        mode = safe(variant.value)
        source_ref = safe(context_id)
        sibling_logic = ("const sibling=document.createElement('iframe');"
                         "sibling.id='sender-sibling';"
                         "sibling.src='/__hackbot_messaging_fixture__/sibling';"
                         "document.body.appendChild(sibling);return;") if variant in {
                             MessageVariant.WRONG_SOURCE, MessageVariant.FRESH_WRONG_SOURCE} else ""
        # The marker is a synthetic local-fixture value, never a request for page contents.
        html = f"""<!doctype html><meta charset=utf-8><title>Messaging proof fixture</title>
<button id=launch type=button>Open controlled victim</button>
<button id=dispatch type=button>Send fixed message</button><div id=state></div>
<script>
const victimUrl={victim}, activation={activation}, portType={port_type};
const safeMethod={method}, mode={mode}, windowMode={safe(binding.window_mode)};
const ownedCanary={safe(binding.owned_canary_value)};
const domField={dom_field}, proofHtml={proof_html}, proofMarker={safe(marker)};
const sourceRef={source_ref};
const state=document.getElementById('state');
const tally={{sent:0, ports:0, rpc:0, received:0, capability:false, effect:'NONE',
             source_attested:false, source_ref:''}};
const trace=[], started=performance.now();
function note(kind) {{
  if (trace.length<16) trace.push([kind,Math.min(12000,Math.max(0,
    Math.floor(performance.now()-started)))]);
  state.setAttribute('data-hackbot-trace',JSON.stringify(trace));
}}
function publish() {{
  for (const [key,value] of Object.entries(tally))
    state.setAttribute('data-hackbot-'+key,String(value));
}}
publish();
document.getElementById('launch').addEventListener('click',() => {{
  function start(victimWindow) {{
    const expected=windowMode==='POPUP' ? openedWindow :
      document.getElementById('victim')?.contentWindow;
    if (!sourceRef || !victimWindow || victimWindow!==expected) return;
    tally.source_attested=true; tally.source_ref=sourceRef; publish();
    note('SOURCE_ATTESTED');
    if (mode==='NO_MESSAGE') return;
    {sibling_logic}
    const kind=mode==='WRONG_TYPE' ? 'HACKBOT_UNRECOGNIZED_TYPE' : activation;
    let channel=null, portTransferred=false;
    if ((mode==='WRONG_TYPE'||mode==='ATTACKER_PORT'||mode==='FRESH_REPRODUCTION'||mode==='TRUSTED'||
         mode==='LOOKALIKE_ORIGIN'||mode==='FRESH_LOOKALIKE_ORIGIN') &&
        (portType || safeMethod)) {{
      channel=new MessageChannel(); tally.ports++; publish();
      note('PORT_CREATED');
      channel.port1.onmessage=(event) => {{
        tally.received++;
        note('RPC_RESPONSE');
        const packet=event.data;
        const small=typeof packet==='string' ? packet.slice(0,256) :
          packet && typeof packet==='object' ? String(packet.value || packet.result || '').slice(0,256) : '';
        if (ownedCanary && small===ownedCanary) {{
          tally.capability=true; tally.effect='OWNED_DATA';
          note('OWNED_MATCH');
        }} else if (small==='HACKBOT_SYNTHETIC_PRIVATE') {{
          tally.capability=true; tally.effect='SYNTHETIC_DATA';
          note('SYNTHETIC_MATCH');
        }} else if (packet && typeof packet==='object' &&
            (packet.type==='RESULT'||packet.type==='response')) {{
          tally.capability=true; tally.effect='UNCLASSIFIED_RPC_RESPONSE';
        }}
        publish();
      }};
    }}
    function send(kind, port) {{
      const message={{type:kind}};
      if (domField) message[domField]=proofHtml;
      if (port) {{ victimWindow.postMessage(message,'*',[port]); portTransferred=true; }}
      else victimWindow.postMessage(message,'*');
      tally.sent++; publish();
      note('MESSAGE_SENT');
      if (port) note('PORT_TRANSFERRED');
    }}
    window.addEventListener('message',event => {{
      if (event.source!==victimWindow) return;
      tally.received++;
      const packet=event.data;
      if (packet && typeof packet==='object' && proofMarker &&
          packet.type==='HACKBOT_DOM_ORIGIN' && packet.marker===proofMarker) {{
        tally.dom_origin=event.origin;
      }} else if (packet && typeof packet==='object' &&
          (packet.type==='READY'||packet.type==='ready')) {{
        note('READY_RECEIVED');
        if (channel && portType && tally.sent<2 && !portTransferred)
          send(portType,channel.port2);
        if (channel && safeMethod && tally.rpc<1) {{
          channel.port1.postMessage({{method:safeMethod}}); tally.rpc++; publish();
          note('RPC_SENT');
        }}
      }} else if (packet && typeof packet==='object' &&
          (packet.type==='RESULT'||packet.type==='response')) {{
        note('RPC_RESPONSE');
        const small=String(packet.value || packet.result || '').slice(0,256);
        if (ownedCanary && small===ownedCanary) {{
          tally.capability=true; tally.effect='OWNED_DATA';
          note('OWNED_MATCH');
        }} else if (small==='HACKBOT_SYNTHETIC_PRIVATE') {{
          tally.capability=true; tally.effect='SYNTHETIC_DATA';
          note('SYNTHETIC_MATCH');
        }} else {{ tally.capability=true; tally.effect='UNCLASSIFIED_RPC_RESPONSE'; }}
      }}
      publish();
    }});
    if (channel && (mode==='WRONG_TYPE'||!portType)) send(kind,channel.port2);
    else send(kind,null);
    if (channel && safeMethod && (mode==='WRONG_TYPE'||!portType) && tally.rpc<1) {{
      channel.port1.postMessage({{method:safeMethod}}); tally.rpc++; publish();
      note('RPC_SENT');
    }}
  }}
  let openedWindow=null;
  if (windowMode==='POPUP') {{
    openedWindow=window.open(victimUrl,'_blank');
    if (openedWindow)
      document.getElementById('dispatch').addEventListener('click',
        () => start(openedWindow),{{once:true}});
  }} else {{
    const victim=document.createElement('iframe'); victim.id='victim'; victim.src=victimUrl;
    victim.addEventListener('load',() => start(victim.contentWindow),{{once:true}});
    document.body.appendChild(victim);
  }}
}});
</script>"""
        return html.encode("utf-8")

    @staticmethod
    def _message_sibling_fixture(binding: MessageExperimentBinding,
                                 marker: str | None = None,
                                 context_id: str | None = None) -> bytes:
        """A same-origin sibling sends the observed protocol from the wrong WindowProxy."""
        safe = lambda value: json.dumps(value, ensure_ascii=True).replace("<", "\\u003c")
        activation = safe(binding.activation_type)
        port_type = safe(binding.port_type)
        method = safe(binding.allowed_method)
        dom_field = safe(binding.dom_field)
        proof_html = safe(
            "<img src=x onerror=\"document.documentElement.setAttribute("
            f"'data-hackbot-dom-proof','{marker}');"
            "(window.opener||window.parent).postMessage({"
            f"type:'HACKBOT_DOM_ORIGIN',marker:'{marker}'"
            "},'*')\">" if marker else "")
        html = f"""<!doctype html><meta charset=utf-8><script>
const activation={activation}, portType={port_type}, safeMethod={method};
const ownedCanary={safe(binding.owned_canary_value)};
const domField={dom_field}, proofHtml={proof_html};
const sourceRef={safe(context_id)};
const victim=parent.document.getElementById('victim').contentWindow;
const state=parent.document.getElementById('state');
let sent=0, rpc=0;
const trace=[], started=performance.now();
function note(kind) {{
  if (trace.length<16) trace.push([kind,Math.min(12000,Math.max(0,
    Math.floor(performance.now()-started)))]);
  state.setAttribute('data-hackbot-trace',JSON.stringify(trace));
}}
function count(key,value) {{ state.setAttribute('data-hackbot-'+key,String(value)); }}
if (!sourceRef || window!==parent.document.getElementById('sender-sibling')?.contentWindow ||
    window===victim || window===parent) throw new Error('sender reference mismatch');
count('source_attested',true); count('source_ref',sourceRef);
note('SOURCE_ATTESTED');
function check(packet) {{
  note('RPC_RESPONSE');
  const value=typeof packet==='string' ? packet.slice(0,256) :
    packet && typeof packet==='object' ? String(packet.value || packet.result || '').slice(0,256) : '';
  if (ownedCanary && value===ownedCanary) {{
    count('capability',true); count('effect','OWNED_DATA');
    note('OWNED_MATCH');
  }} else if (value==='HACKBOT_SYNTHETIC_PRIVATE') {{
    count('capability',true); count('effect','SYNTHETIC_DATA');
    note('SYNTHETIC_MATCH');
  }} else if (packet && typeof packet==='object' &&
             (packet.type==='RESULT'||packet.type==='response')) {{
    count('capability',true); count('effect','UNCLASSIFIED_RPC_RESPONSE');
  }}
}}
const channel=(portType || safeMethod) ? new MessageChannel() : null;
if (channel) {{
  count('ports',1);
  note('PORT_CREATED');
  channel.port1.onmessage=event => check(event.data);
}}
function send(kind,port) {{
  const message={{type:kind}};
  if (domField) message[domField]=proofHtml;
  if (port) victim.postMessage(message,'*',[port]);
  else victim.postMessage(message,'*');
  count('sent',++sent);
  note('MESSAGE_SENT');
  if (port) note('PORT_TRANSFERRED');
}}
function call() {{
  if (channel && safeMethod && rpc<1) {{
    channel.port1.postMessage({{method:safeMethod}}); count('rpc',++rpc);
    note('RPC_SENT');
  }}
}}
window.addEventListener('message',event => {{
  if (event.source!==victim) return;
  const packet=event.data;
  if (packet && typeof packet==='object' &&
      (packet.type==='READY'||packet.type==='ready')) {{
    note('READY_RECEIVED');
    if (channel && portType && sent<2) send(portType,channel.port2);
    call();
  }} else check(packet);
}});
if (channel && !portType) send(activation,channel.port2);
else send(activation,null);
if (channel && !portType) call();
</script>"""
        return html.encode("utf-8")

    def execute_message_trial(self, session_id: str, binding: MessageExperimentBinding,
                              variant: MessageVariant,
                              gate: Callable[[str, str, bool], str | bool | None], *,
                              authenticated: bool, request_cap: int,
                              timeout_ms: int) -> MessageBrowserObservation:
        """Run one isolated local sender against a policy-gated victim route."""
        source = self._contexts.get(session_id)
        proxy = self._proxy_settings.get(session_id)
        if source is None or proxy is None or self._playwright is None:
            raise BrowserError("Verified browser session is not running")
        if proxy.capture_required and proxy.ca_certificate is not None:
            raise BrowserError("Fresh-context proxy trust is not configured")
        if not 1 <= request_cap <= 48 or not 1000 <= timeout_ms <= 20000:
            raise BrowserError("Messaging browser budget is invalid")
        victim_parts = urlsplit(binding.route_url)
        if victim_parts.scheme not in {"http", "https"} or not victim_parts.hostname:
            raise BrowserError("Invalid victim browser route")
        trusted_origin = f"{victim_parts.scheme}://{victim_parts.netloc}"
        foreign_origin = "http://attacker.fixture.invalid"
        probe_origin = (lookalike_origin(binding.route_url, binding.origin_probe_kind)
                        if variant in {MessageVariant.LOOKALIKE_ORIGIN,
                                       MessageVariant.FRESH_LOOKALIKE_ORIGIN} else None)
        origin = (trusted_origin if variant in {MessageVariant.TRUSTED,
                                              MessageVariant.WRONG_SOURCE,
                                              MessageVariant.FRESH_WRONG_SOURCE}
                  else probe_origin if variant in {
                      MessageVariant.LOOKALIKE_ORIGIN,
                      MessageVariant.FRESH_LOOKALIKE_ORIGIN} else foreign_origin)
        fixture_url = origin + "/__hackbot_messaging_fixture__/sender"
        marker = "MSGDOM-" + uuid.uuid4().hex if binding.dom_field else None
        context_id = "MSGCTX-" + uuid.uuid4().hex
        fixture_body = self._message_fixture(binding, variant, marker, context_id)
        sibling_url = origin + "/__hackbot_messaging_fixture__/sibling"
        sibling_body = self._message_sibling_fixture(binding, marker, context_id)
        options = {"headless": True, "chromium_sandbox": False}
        if self._executable_path is not None:
            options["executable_path"] = str(self._executable_path)
        if proxy.enabled:
            options["proxy"] = {"server": proxy.proxy_url}
        try:
            browser = self._playwright.chromium.launch(**options)
            state = source.storage_state() if authenticated else None
        except Exception:
            raise BrowserError("Fresh messaging browser context could not start") from None
        context = None
        request_count = 0
        denied = 0
        bundle_sha256 = None
        victim_status = None
        victim_headers: dict[str, str] = {}
        try:
            context = browser.new_context(storage_state=state, accept_downloads=False,
                                          ignore_https_errors=False, service_workers="block")

            def handle(route) -> None:
                nonlocal request_count, denied, bundle_sha256, victim_status, victim_headers
                request = route.request
                if request.url == fixture_url:
                    route.fulfill(status=200, content_type="text/html; charset=utf-8",
                                  body=fixture_body)
                    return
                if variant in {MessageVariant.WRONG_SOURCE,
                               MessageVariant.FRESH_WRONG_SOURCE} and request.url == sibling_url:
                    route.fulfill(status=200, content_type="text/html; charset=utf-8",
                                  body=sibling_body)
                    return
                request_count += 1
                try:
                    ticket = (gate(request.url, request.method,
                                   request.is_navigation_request())
                              if request_count <= request_cap else None)
                except Exception:
                    denied += 1
                    try:
                        route.abort()
                    except Exception:
                        pass
                    return
                if not ticket:
                    denied += 1
                    route.abort()
                    return
                release = getattr(gate, "release", None)
                released = False
                try:
                    response = route.fetch(max_redirects=0, timeout=min(timeout_ms, 5000))
                    if 300 <= response.status < 400:
                        # Playwright does not route every hop of a browser redirect chain.
                        denied += 1
                        route.abort()
                        return
                    if int(response.headers.get("content-length", "0")) > 2_097_152:
                        denied += 1
                        route.abort()
                        return
                    if request.url == binding.asset_url and response.status == 200:
                        body = response.body()
                        if len(body) > 1_048_576:
                            denied += 1
                            route.abort()
                            return
                        bundle_sha256 = hashlib.sha256(body).hexdigest()
                    if request.url == binding.route_url:
                        victim_status = response.status
                        victim_headers = response.headers
                    if callable(release):
                        release(ticket)
                        released = True
                    route.fulfill(response=response)
                except Exception:
                    denied += 1
                    try:
                        route.abort()
                    except Exception:
                        pass
                finally:
                    if callable(release) and not released:
                        release(ticket)

            context.route("**/*", handle)
            page = context.new_page()
            error_code = None
            try:
                page.goto(fixture_url, wait_until="domcontentloaded", timeout=timeout_ms)
                if binding.window_mode == "POPUP":
                    with page.expect_popup(timeout=timeout_ms) as popup_info:
                        page.locator("#launch").click(timeout=timeout_ms)
                    popup_info.value.wait_for_load_state("load", timeout=timeout_ms)
                    page.locator("#dispatch").click(timeout=timeout_ms)
                else:
                    page.locator("#launch").click(timeout=timeout_ms)
                page.wait_for_timeout(min(1200, timeout_ms // 3))
            except Exception:
                error_code = "MESSAGING_FIXTURE_FAILED"
            state_node = page.locator("#state")

            def read(name: str) -> str | None:
                try:
                    return state_node.get_attribute("data-hackbot-" + name, timeout=500)
                except Exception:
                    return None

            def number(name: str) -> int:
                value = read(name)
                return int(value) if value and value.isdecimal() else 0

            effect = read("effect")
            capability = read("capability") == "true"
            try:
                trace_data = json.loads(read("trace") or "[]")
                trace = tuple((part[0], part[1]) for part in trace_data
                              if isinstance(part, list) and len(part) == 2)
            except (TypeError, ValueError, json.JSONDecodeError):
                trace = ()
            marker_context = None
            document_origin = None
            sandbox_flags: list[str] = []
            for current_page in context.pages[:4]:
                for frame in current_page.frames[:8]:
                    if frame.url != binding.route_url:
                        continue
                    try:
                        for iframe in frame.locator("iframe").all()[:8]:
                            value = iframe.get_attribute("sandbox", timeout=500)
                            if value is not None:
                                sandbox_flags.append(value[:120])
                    except Exception:
                        pass
            if marker is not None:
                for current_page in context.pages[:4]:
                    for frame in current_page.frames[:8]:
                        if frame.url != binding.route_url:
                            continue
                        try:
                            observed = frame.locator("html").get_attribute(
                                "data-hackbot-dom-proof", timeout=500)
                        except Exception:
                            observed = None
                        if observed == marker:
                            capability = True
                            effect = "DOM_EXECUTION"
                            if len(trace) < 16:
                                trace += (("DOM_EXECUTION", trace[-1][1] if trace else 0),)
                            marker_context = ("MAIN" if frame == current_page.main_frame
                                              else "IFRAME")
                            document_origin = read("dom_origin")
                            break
                    if marker_context:
                        break
            return MessageBrowserObservation(
                context_id=context_id, attacker_origin=origin,
                source_relationship=("SIBLING_FRAME" if variant in {
                    MessageVariant.WRONG_SOURCE, MessageVariant.FRESH_WRONG_SOURCE}
                                     else "FIXTURE_OPENER_OF_VICTIM"
                                     if binding.window_mode == "POPUP"
                                     else "FIXTURE_PARENT_OF_VICTIM"),
                source_attested=(read("source_attested") == "true" and
                                 read("source_ref") == context_id),
                event_trace=trace,
                message_type=(None if variant is MessageVariant.NO_MESSAGE else
                              "HACKBOT_UNRECOGNIZED_TYPE" if variant is MessageVariant.WRONG_TYPE
                              else binding.activation_type),
                message_count=number("sent"), port_count=number("ports"),
                rpc_calls=number("rpc"), capability_observed=capability,
                effect_kind=effect if effect not in {None, "NONE"} else None,
                effect_fingerprint=(hashlib.sha256(marker.encode()).hexdigest()
                                    if capability and effect == "DOM_EXECUTION" and marker
                                    else hashlib.sha256(binding.owned_canary_value.encode()).hexdigest()
                                    if capability and effect == "OWNED_DATA" and
                                    binding.owned_canary_value
                                    else hashlib.sha256(b"HACKBOT_SYNTHETIC_PRIVATE").hexdigest()
                                    if capability and effect == "SYNTHETIC_DATA" else None),
                victim_bundle_sha256=bundle_sha256, response_status=victim_status,
                frame_ancestors=next((part.strip() for part in
                    victim_headers.get("content-security-policy", "").split(";")
                    if part.strip().lower().startswith("frame-ancestors ")), None),
                x_frame_options=victim_headers.get("x-frame-options"),
                sandbox_flags=tuple(sandbox_flags[:8]),
                request_count=request_count, denial_count=denied, error_code=error_code,
                marker_context=marker_context, document_origin=document_origin,
            )
        finally:
            if context is not None:
                try:
                    context.close()
                except Exception:
                    pass
            browser.close()
