"""Bounded static classification of protected, current client artifacts."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import ipaddress
import json
import math
import re
from urllib.parse import urlsplit

from .exposure_models import ExposureCategory, ExposureStatus


MAX_JS_SCAN_BYTES = 1_048_576
MAX_MAP_SCAN_BYTES = 8_388_608
MAX_MAP_SOURCES = 32
MAX_SIGNALS = 128

_ASSIGNMENT = re.compile(
    r"(?P<key_quote>['\"]?)(?P<key>[A-Za-z_$][A-Za-z0-9_$.-]{2,79})"
    r"(?P=key_quote)\s*[:=]\s*"
    r"(?P<quote>['\"])(?P<value>[^'\"\r\n]{4,2048})(?P=quote)"
)
_KEY = re.compile(r"(?i)(?:password|passwd|passphrase|client_secret|private_key|secret|"
                  r"access_token|refresh_token|auth_token|api_key|access_key|database_url|"
                  r"db_url|redis_url|connection_string|webhook_secret|signing_key)")
_PUBLIC_KEY = re.compile(r"(?i)(?:^|[_.$-])(?:client_id|public_key|publishable_key|"
                         r"sentry_dsn|recaptcha_site_key|analytics_key|firebase_api_key|"
                         r"feature_flag_key)(?:$|[_.$-])")
_PUBLIC_PREFIX = re.compile(r"(?i)^(?:NEXT_PUBLIC_|REACT_APP_|VITE_|VUE_APP_|NUXT_PUBLIC_|PUBLIC_)")
_PLACEHOLDER = re.compile(r"(?i)(?:^|[^a-z])(?:changeme|placeholder|example|sample|dummy|"
                          r"your[_ -]?(?:key|token|secret|password)|not[_ -]?a[_ -]?secret|"
                          r"fake|replace[_ -]?me)(?:$|[^a-z])")
_KNOWN_CREDENTIAL = re.compile(r"(?:AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|"
                               r"gh[pousr]_[A-Za-z0-9_]{24,}|sk_live_[A-Za-z0-9]{16,}|"
                               r"xox[baprs]-[A-Za-z0-9-]{15,})\Z")
_KNOWN_CREDENTIAL_IN_TEXT = re.compile(r"(?<![A-Za-z0-9_])(?:AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|"
                                       r"gh[pousr]_[A-Za-z0-9_]{24,}|sk_live_[A-Za-z0-9]{16,}|"
                                       r"xox[baprs]-[A-Za-z0-9-]{15,})(?![A-Za-z0-9_])")
_PRIVATE_KEY_BLOCK = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
                                r".{16,7900}?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.S)
_URL = re.compile(r"https?://[A-Za-z0-9._~:%+-]{1,200}(?:/[A-Za-z0-9._~/%+-]{0,120})?", re.I)
_SIGNED_URL = re.compile(r"https?://[^\s'\"<>]{1,2048}", re.I)
_SIGNED_PARAMETERS = frozenset({"x-amz-signature", "x-goog-signature", "signature", "sig", "se"})


@dataclass(frozen=True, slots=True)
class StaticExposureSignal:
    category: ExposureCategory
    fingerprint_sha256: str
    credential_type: str | None
    value_length: int | None
    service_class: str
    potential_privilege: str
    status: ExposureStatus
    confidence: int
    priority: int
    reason_codes: tuple[str, ...]
    source_index: int
    referenced_host: str | None = None
    referenced_port: int | None = None


@dataclass(frozen=True, slots=True)
class StaticExposureAnalysis:
    signals: tuple[StaticExposureSignal, ...]
    bytes_examined: int
    source_files_examined: int
    truncated: bool
    parse_error: bool


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    frequencies = {char: value.count(char) for char in set(value)}
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in frequencies.values())


def _internal_host(host: str) -> str | None:
    normalized = host.lower().rstrip(".")
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        address = None
    if address is not None:
        return "PRIVATE_IP" if not address.is_global else None
    if normalized == "localhost" or normalized.endswith((".localhost", ".local", ".internal",
                                                         ".corp", ".svc", ".cluster.local")):
        return "INTERNAL_DNS"
    if ".svc." in normalized or normalized.startswith(("kubernetes.", "metadata.")):
        return "SERVICE_DISCOVERY"
    return None


def _classify_credential(key: str, value: str, *, source_map: bool,
                         source_index: int, application_usage: bool = False) -> StaticExposureSignal | None:
    if not (_KEY.search(key) or _KNOWN_CREDENTIAL.fullmatch(value)):
        return None
    digest = hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()
    normalized = re.sub(r"[^a-z0-9]", "_", key.lower())
    public = bool(_PUBLIC_KEY.search(key) or _PUBLIC_PREFIX.match(key))
    placeholder = (bool(_PLACEHOLDER.search(value)) or value.lower() in {
        "password", "secret", "test", "testing", "development", "null", "undefined", "123456",
    } or len(set(value)) <= 3)
    if placeholder:
        return StaticExposureSignal(
            ExposureCategory.SOURCE_MAP_SECRET if source_map else ExposureCategory.JS_SECRET,
            digest, "PLACEHOLDER", len(value), "UNKNOWN", "NONE",
            ExposureStatus.REJECTED_PLACEHOLDER, 5, 0, ("PLACEHOLDER_VALUE",), source_index)
    if public:
        return StaticExposureSignal(
            ExposureCategory.SOURCE_MAP_SECRET if source_map else ExposureCategory.JS_SECRET,
            digest, "PUBLIC_IDENTIFIER", len(value), "BROWSER_CONFIG", "NONE",
            ExposureStatus.REJECTED_PUBLIC, 10, 0, ("PUBLIC_BY_DESIGN",), source_index)

    known = bool(_KNOWN_CREDENTIAL.fullmatch(value))
    private_key = "private_key" in normalized or "signing_key" in normalized
    connection = any(label in normalized for label in ("database_url", "db_url", "redis_url", "connection_string"))
    credential_type = ("PRIVATE_KEY" if private_key else "CONNECTION_STRING" if connection else
                       "KNOWN_FORMAT_TOKEN" if known else "PASSWORD" if "password" in normalized or
                       "passwd" in normalized else "CLIENT_SECRET" if "client_secret" in normalized else
                       "TOKEN" if "token" in normalized else "API_KEY" if "key" in normalized else "SECRET")
    service = ("CLOUD" if value.startswith(("AKIA", "ASIA")) else
               "GITHUB" if value.startswith("gh") and known else
               "DATABASE" if connection else "APPLICATION")
    entropy = _entropy(value)
    score = 25 + (30 if known else 0) + (25 if private_key or connection else 0)
    score += 20 if any(label in normalized for label in (
        "client_secret", "password", "passwd", "refresh_token", "signing_key")) else 0
    score += 20 if len(value) >= 16 and entropy >= 3.3 else 0
    score += 10 if any(word in normalized for word in ("production", "prod", "live")) else 0
    score += 15 if application_usage else 0
    if value.lower().startswith(("test_", "dev_", "sandbox_")):
        score -= 30
    score = max(0, min(score, 100))
    status = (ExposureStatus.FORMAT_VALID if known or private_key or connection or score >= 60
              else ExposureStatus.NEEDS_RESEARCH)
    return StaticExposureSignal(
        ExposureCategory.SOURCE_MAP_SECRET if source_map else ExposureCategory.JS_SECRET,
        digest, credential_type, len(value), service,
        "POTENTIALLY_PRIVILEGED" if score >= 60 else "UNKNOWN", status,
        score, min(100, score + (10 if source_map else 0)),
        tuple(code for condition, code in (
            (known, "KNOWN_CREDENTIAL_FORMAT"),
            (private_key, "PRIVATE_KEY_CONTEXT"),
            (connection, "CONNECTION_STRING_CONTEXT"),
            (len(value) >= 16 and entropy >= 3.3, "HIGH_ENTROPY"),
            (application_usage, "APPLICATION_REQUEST_USAGE"),
            (source_map, "SOURCE_MAP_CONTEXT"),
        ) if condition) or ("SENSITIVE_KEY_NAME",), source_index)


def _scan_text(text: str, *, source_map: bool, source_index: int,
               max_signals: int) -> tuple[StaticExposureSignal, ...]:
    results: list[StaticExposureSignal] = []
    seen: set[str] = set()
    for match in _ASSIGNMENT.finditer(text):
        key = match.group("key")
        usage = bool(re.search(
            r"(?i)(?:authorization|x-api-key|clientsecret|api_key|apikey)"
            r"[^\r\n]{0,160}\b" + re.escape(key) + r"\b",
            text[match.end():match.end() + 4096]))
        signal = _classify_credential(match.group("key"), match.group("value"),
                                      source_map=source_map, source_index=source_index,
                                      application_usage=usage)
        if signal and signal.fingerprint_sha256 not in seen:
            results.append(signal)
            seen.add(signal.fingerprint_sha256)
            if len(results) >= max_signals:
                return tuple(results)
    for match in _KNOWN_CREDENTIAL_IN_TEXT.finditer(text):
        value = match.group(0)
        fingerprint = hashlib.sha256(value.encode()).hexdigest()
        if fingerprint in seen:
            continue
        signal = _classify_credential("credential", value, source_map=source_map,
                                      source_index=source_index)
        if signal is not None:
            results.append(signal)
            seen.add(fingerprint)
        if len(results) >= max_signals:
            return tuple(results)
    for match in _PRIVATE_KEY_BLOCK.finditer(text):
        value = match.group(0)
        fingerprint = hashlib.sha256(value.encode()).hexdigest()
        if fingerprint in seen:
            continue
        results.append(StaticExposureSignal(
            ExposureCategory.SOURCE_MAP_SECRET if source_map else ExposureCategory.JS_SECRET,
            fingerprint, "PRIVATE_KEY", len(value), "APPLICATION", "POTENTIALLY_PRIVILEGED",
            ExposureStatus.FORMAT_VALID, 95, 95,
            ("PRIVATE_KEY_BLOCK",) + (("SOURCE_MAP_CONTEXT",) if source_map else ()), source_index))
        seen.add(fingerprint)
        if len(results) >= max_signals:
            return tuple(results)
    for match in _SIGNED_URL.finditer(text):
        raw = match.group(0).rstrip("),;}")
        try:
            parsed = urlsplit(raw)
            names = {part.partition("=")[0].lower() for part in parsed.query.split("&")}
        except ValueError:
            continue
        if not names.intersection(_SIGNED_PARAMETERS) or len(raw) > 2048:
            continue
        fingerprint = hashlib.sha256(raw.encode()).hexdigest()
        if fingerprint in seen:
            continue
        results.append(StaticExposureSignal(
            ExposureCategory.SOURCE_MAP_SECRET if source_map else ExposureCategory.JS_SECRET,
            fingerprint, "SIGNED_URL", len(raw), "OBJECT_STORAGE", "UNKNOWN",
            ExposureStatus.NEEDS_RESEARCH, 45, 45,
            ("SIGNED_URL_CANDIDATE", "EXPIRY_AND_AUDIENCE_UNPROVEN"), source_index))
        seen.add(fingerprint)
        if len(results) >= max_signals:
            return tuple(results)
    for match in _URL.finditer(text):
        try:
            parsed = urlsplit(match.group(0))
            host = parsed.hostname or ""
            port = parsed.port
        except ValueError:
            continue
        reason = _internal_host(host)
        if reason is None:
            continue
        context = text[max(0, match.start() - 256):match.end() + 256]
        vhost_hint = bool(re.search(r"(?i)(?:virtual[_-]?host|vhost|host[_-]?header|['\"]Host['\"])",
                                    context))
        fingerprint = hashlib.sha256(f"{host}:{port or ''}".encode()).hexdigest()
        if fingerprint in seen:
            continue
        results.append(StaticExposureSignal(
            ExposureCategory.INTERNAL_VHOST_CANDIDATE if vhost_hint else
            ExposureCategory.INTERNAL_HOST_DISCLOSURE, fingerprint, None, None,
            "INTERNAL_SERVICE", "UNKNOWN", ExposureStatus.NEEDS_RESEARCH,
            45 if vhost_hint else 35, 50 if vhost_hint else 35,
            (reason, "VHOST_ROUTING_HINT" if vhost_hint else "NO_EXTERNAL_REACHABILITY_PROOF"),
            source_index,
            referenced_host=host.lower(), referenced_port=port))
        seen.add(fingerprint)
        if len(results) >= max_signals:
            break
    return tuple(results)


class ExposureStaticAnalyzer:
    """Scan only the supplied current artifact; never execute or fetch target content."""

    def analyze_js(self, body: bytes) -> StaticExposureAnalysis:
        if not isinstance(body, bytes):
            raise TypeError("JavaScript body must be bytes")
        selected = body[:MAX_JS_SCAN_BYTES]
        signals = _scan_text(selected.decode("utf-8", "replace"), source_map=False,
                             source_index=0, max_signals=MAX_SIGNALS)
        return StaticExposureAnalysis(signals, len(selected), 1, len(body) > len(selected), False)

    def analyze_source_map(self, body: bytes) -> StaticExposureAnalysis:
        if not isinstance(body, bytes):
            raise TypeError("Source map body must be bytes")
        if len(body) > MAX_MAP_SCAN_BYTES:
            return StaticExposureAnalysis((), 0, 0, True, False)
        try:
            document = json.loads(body)
        except (ValueError, UnicodeDecodeError):
            return StaticExposureAnalysis((), len(body), 0, False, True)
        if not isinstance(document, dict) or not isinstance(document.get("sourcesContent"), list):
            return StaticExposureAnalysis((), len(body), 0, False, True)
        contents = document["sourcesContent"]
        signals: list[StaticExposureSignal] = []
        seen: set[str] = set()
        examined = 0
        truncated = len(contents) > MAX_MAP_SOURCES
        for index, content in enumerate(contents[:MAX_MAP_SOURCES]):
            if not isinstance(content, str):
                continue
            selected = content[:MAX_JS_SCAN_BYTES]
            truncated |= len(content) > len(selected)
            examined += 1
            for signal in _scan_text(selected, source_map=True, source_index=index,
                                     max_signals=MAX_SIGNALS - len(signals)):
                if signal.fingerprint_sha256 in seen:
                    continue
                signals.append(signal)
                seen.add(signal.fingerprint_sha256)
            if len(signals) >= MAX_SIGNALS:
                truncated = True
                break
        return StaticExposureAnalysis(tuple(signals), len(body), examined, truncated, False)
