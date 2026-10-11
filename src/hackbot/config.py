"""Local-only, typed Phase 1 configuration."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
import tomllib
from typing import Mapping
from urllib.parse import urlsplit


class ConfigError(ValueError):
    """Invalid local configuration. Messages must not include input values."""


@dataclass(frozen=True)
class LocalPaths:
    config_file: Path
    root: Path

    @property
    def state(self) -> Path:
        return self.root / "state"

    @property
    def artifacts(self) -> Path:
        return self.root / "artifacts"

    @property
    def logs(self) -> Path:
        return self.root / "logs"

    @property
    def evidence(self) -> Path:
        return self.artifacts / "evidence"

    @property
    def temporary(self) -> Path:
        return self.root / "tmp"


@dataclass(frozen=True)
class AppConfig:
    paths: LocalPaths
    log_level: str = "INFO"
    recon: ReconSettings | None = None
    store: StoreSettings | None = None
    targets: TargetSettings | None = None
    secrets: SecretSettings | None = None
    browser: BrowserSettings | None = None
    burp: BurpSettings | None = None
    executor: ExecutorSettings | None = None


@dataclass(frozen=True)
class ReconSettings:
    dsn_env: str = "HACKBOT_RECON_DSN"
    max_page_size: int = 50
    statement_timeout_ms: int = 3000


@dataclass(frozen=True)
class StoreSettings:
    artifact_root: Path
    max_inline_bytes: int = 2048
    max_page_size: int = 50


@dataclass(frozen=True)
class TargetSettings:
    root: Path


@dataclass(frozen=True)
class SecretBindingConfig:
    ref: str
    provider_ref: str
    kind: str

    def __post_init__(self) -> None:
        if not isinstance(self.ref, str) or not re.fullmatch(
            r"(?:ref:)?[a-z][a-z0-9_-]{0,63}(?:/[a-z][a-z0-9_-]{0,63})?", self.ref
        ):
            raise ConfigError("Invalid opaque secret reference")
        if not isinstance(self.provider_ref, str) or not (
            re.fullmatch(r"env:[A-Z][A-Z0-9_]*", self.provider_ref)
            or re.fullmatch(r"manual:[a-z][a-z0-9_-]{0,63}", self.provider_ref)
        ):
            raise ConfigError("Invalid secret provider reference")
        if not isinstance(self.kind, str) or self.kind not in {"PASSWORD", "COOKIE", "BEARER_TOKEN", "API_TOKEN",
                             "LOGIN_DESCRIPTOR", "HEADER_SET", "SESSION_IMPORT_REFERENCE", "UNKNOWN"}:
            raise ConfigError("Invalid secret kind")


@dataclass(frozen=True)
class SecretSettings:
    allowed_env_prefixes: tuple[str, ...] = ("HACKBOT_SECRET_",)
    bindings: tuple[SecretBindingConfig, ...] = ()

    def __post_init__(self) -> None:
        prefixes = self.allowed_env_prefixes
        if (not isinstance(prefixes, tuple) or not prefixes or len(prefixes) > 16
                or any(not isinstance(prefix, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]*_", prefix)
                       for prefix in prefixes) or len(set(prefixes)) != len(prefixes)):
            raise ConfigError("Invalid allowed secret environment prefixes")
        if (not isinstance(self.bindings, tuple) or len(self.bindings) > 256
                or any(not isinstance(binding, SecretBindingConfig) for binding in self.bindings)
                or len({binding.ref for binding in self.bindings}) != len(self.bindings)):
            raise ConfigError("Invalid secret reference mapping")
        for binding in self.bindings:
            if binding.provider_ref.startswith("env:") and not any(
                binding.provider_ref[4:].startswith(prefix) for prefix in prefixes
            ):
                raise ConfigError("Secret environment reference is outside allowed prefixes")


@dataclass(frozen=True)
class BrowserSettings:
    profile_root: Path
    display: str | None = None
    vnc_url: str | None = None
    chromium_executable: Path | None = None
    max_sessions: int = 20
    max_page_size: int = 50

    def __post_init__(self) -> None:
        if (not isinstance(self.profile_root, Path) or not self.profile_root.is_absolute()
                or ".." in self.profile_root.parts):
            raise ConfigError("Browser profile root must be absolute")
        if self.display is not None and (not isinstance(self.display, str)
                                         or not re.fullmatch(r":\d{3,4}", self.display)
                                         or int(self.display[1:]) == 99):
            raise ConfigError("Invalid dedicated browser display")
        if self.vnc_url is not None:
            if not isinstance(self.vnc_url, str):
                raise ConfigError("Invalid dedicated VNC endpoint")
            try:
                parsed = urlsplit(self.vnc_url)
                valid = (parsed.scheme == "http" and parsed.hostname == "127.0.0.1"
                         and parsed.port is not None and parsed.port != 6080
                         and parsed.path == "/vnc.html" and not parsed.username
                         and not parsed.password and not parsed.query and not parsed.fragment)
            except ValueError:
                valid = False
            if not valid:
                raise ConfigError("Invalid dedicated VNC endpoint")
        if self.vnc_url is not None and self.display is None:
            raise ConfigError("Dedicated VNC endpoint requires a browser display")
        if self.chromium_executable is not None and (
            not isinstance(self.chromium_executable, Path) or not self.chromium_executable.is_absolute()
            or ".." in self.chromium_executable.parts
        ):
            raise ConfigError("Chromium executable must be an absolute path")
        if type(self.max_sessions) is not int or not 1 <= self.max_sessions <= 100:
            raise ConfigError("Browser max_sessions must be between 1 and 100")
        if type(self.max_page_size) is not int or not 1 <= self.max_page_size <= 100:
            raise ConfigError("Browser max_page_size must be between 1 and 100")


@dataclass(frozen=True)
class BurpSettings:
    enabled: bool
    project_root: Path
    installation_jar: Path | None = None
    ca_certificate: Path | None = None
    listener_start: int = 38080
    listener_end: int = 38179
    bridge_port: int = 38777
    bridge_secret_ref: str | None = None
    max_event_bytes: int = 1_048_576
    max_inflight: int = 8
    third_party_capture: str = "DROP"

    def __post_init__(self) -> None:
        if type(self.enabled) is not bool:
            raise ConfigError("Invalid Burp enabled flag")
        for path in (self.project_root, self.installation_jar, self.ca_certificate):
            if path is not None and (not isinstance(path, Path) or not path.is_absolute()
                                     or ".." in path.parts):
                raise ConfigError("Burp paths must be absolute")
        if (type(self.listener_start) is not int or type(self.listener_end) is not int
                or not 1024 <= self.listener_start <= self.listener_end <= 65535
                or self.listener_end - self.listener_start > 255):
            raise ConfigError("Invalid Burp listener range")
        if (type(self.bridge_port) is not int or not 1024 <= self.bridge_port <= 65535
                or self.listener_start <= self.bridge_port <= self.listener_end):
            raise ConfigError("Invalid Burp bridge port")
        if self.bridge_secret_ref is not None and (not isinstance(self.bridge_secret_ref, str)
                or not re.fullmatch(r"(?:ref:)?[a-z][a-z0-9_-]{0,63}(?:/[a-z][a-z0-9_-]{0,63})?",
                                    self.bridge_secret_ref)):
            raise ConfigError("Invalid Burp bridge secret reference")
        if type(self.max_event_bytes) is not int or not 4096 <= self.max_event_bytes <= 8_388_608:
            raise ConfigError("Invalid Burp event size limit")
        if type(self.max_inflight) is not int or not 1 <= self.max_inflight <= 32:
            raise ConfigError("Invalid Burp bridge concurrency limit")
        if self.third_party_capture not in {"DROP", "METADATA_ONLY"}:
            raise ConfigError("Invalid third-party capture policy")


@dataclass(frozen=True)
class ExecutorSettings:
    allow_direct: bool = False
    capture_required: bool = False
    connect_timeout_seconds: float = 3.0
    read_timeout_seconds: float = 10.0
    overall_timeout_seconds: float = 30.0
    max_redirects: int = 3
    max_request_bytes: int = 262144
    max_response_bytes: int = 262144

    def __post_init__(self) -> None:
        if type(self.allow_direct) is not bool or type(self.capture_required) is not bool:
            raise ConfigError("Invalid executor routing policy")
        for value in (self.connect_timeout_seconds, self.read_timeout_seconds, self.overall_timeout_seconds):
            if type(value) not in (int, float) or not 0.1 <= value <= 120:
                raise ConfigError("Invalid executor timeout")
        if self.overall_timeout_seconds < self.connect_timeout_seconds:
            raise ConfigError("Executor overall timeout is too short")
        if type(self.max_redirects) is not int or not 0 <= self.max_redirects <= 10:
            raise ConfigError("Invalid executor redirect limit")
        for value in (self.max_request_bytes, self.max_response_bytes):
            if type(value) is not int or not 1024 <= value <= 1048576:
                raise ConfigError("Invalid executor capture limit")


_LOG_LEVELS = frozenset({"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"})


def _path(value: str, *, base: Path) -> Path:
    if not value.strip() or "\x00" in value:
        raise ConfigError("Invalid local path configuration")
    try:
        candidate = Path(value).expanduser()
        return (candidate if candidate.is_absolute() else base / candidate).resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ConfigError("Invalid local path configuration") from exc


def _table(data: object, allowed: frozenset[str], label: str) -> dict[str, object]:
    if not isinstance(data, dict) or any(not isinstance(key, str) for key in data):
        raise ConfigError(f"Invalid {label} configuration")
    if set(data) - allowed:
        raise ConfigError(f"Unsupported {label} configuration key")
    return data


def load_config(
    config_file: Path | None = None, *, environ: Mapping[str, str] | None = None
) -> AppConfig:
    """Load optional TOML; an explicit missing file is an error. Never creates paths."""

    env = os.environ if environ is None else environ
    home = Path(env.get("HOME", str(Path.home()))).expanduser().resolve(strict=False)
    config_home = _path(env.get("XDG_CONFIG_HOME", str(home / ".config")), base=home)
    state_home = _path(env.get("XDG_STATE_HOME", str(home / ".local/state")), base=home)

    selected = config_file if config_file is not None else env.get("HACKBOT_CONFIG")
    explicit = selected is not None
    file_path = (
        _path(str(selected), base=Path.cwd())
        if explicit
        else config_home / "bughunter-agent/config.toml"
    )

    data: dict[str, object] = {}
    try:
        if file_path.is_file():
            with file_path.open("rb") as handle:
                data = tomllib.load(handle)
        elif explicit or file_path.exists():
            raise ConfigError("Configuration file is missing or is not a regular file")
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError("Cannot read or parse configuration file") from exc

    top = _table(data, frozenset({"paths", "logging", "recon", "store", "targets", "secrets", "browser", "burp", "executor"}), "top-level")
    paths = _table(top.get("paths", {}), frozenset({"root"}), "paths")
    logging = _table(top.get("logging", {}), frozenset({"level"}), "logging")
    recon_table = _table(
        top.get("recon", {}),
        frozenset({"dsn_env", "max_page_size", "statement_timeout_ms"}),
        "recon",
    )
    store_table = _table(
        top.get("store", {}),
        frozenset({"artifact_root", "max_inline_bytes", "max_page_size"}),
        "store",
    )
    targets_table = _table(top.get("targets", {}), frozenset({"root"}), "targets")
    secrets_table = _table(top.get("secrets", {}), frozenset({"allowed_env_prefixes", "references"}), "secrets")
    browser_table = _table(top.get("browser", {}),
                           frozenset({"profile_root", "display", "vnc_url", "chromium_executable",
                                      "max_sessions", "max_page_size"}),
                           "browser")
    burp_table = _table(top.get("burp", {}),
                        frozenset({"enabled", "project_root", "installation_jar", "ca_certificate",
                                   "listener_start", "listener_end", "bridge_port", "bridge_secret_ref",
                                   "max_event_bytes", "max_inflight", "third_party_capture"}), "burp")
    executor_table = _table(top.get("executor", {}),
                            frozenset({"allow_direct", "capture_required", "connect_timeout_seconds",
                                       "read_timeout_seconds", "overall_timeout_seconds", "max_redirects",
                                       "max_request_bytes", "max_response_bytes"}), "executor")

    if "root" in paths:
        configured_root = paths["root"]
        base = file_path.parent
    elif "HACKBOT_HOME" in env:
        configured_root = env["HACKBOT_HOME"]
        base = Path.cwd()
    else:
        configured_root = str(state_home / "bughunter-agent")
        base = file_path.parent
    if not isinstance(configured_root, str):
        raise ConfigError("Local state root must be a path string")
    root = _path(configured_root, base=base)

    level = logging.get("level", "INFO")
    if not isinstance(level, str) or level.upper() not in _LOG_LEVELS:
        raise ConfigError("Unsupported logging level")

    dsn_env = recon_table.get("dsn_env", "HACKBOT_RECON_DSN")
    max_page_size = recon_table.get("max_page_size", 50)
    timeout = recon_table.get("statement_timeout_ms", 3000)
    if not isinstance(dsn_env, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]*", dsn_env):
        raise ConfigError("Invalid recon credential environment reference")
    if type(max_page_size) is not int or not 1 <= max_page_size <= 100:
        raise ConfigError("Recon max_page_size must be between 1 and 100")
    if type(timeout) is not int or not 100 <= timeout <= 5000:
        raise ConfigError("Recon statement_timeout_ms must be between 100 and 5000")

    artifact_root_value = store_table.get("artifact_root")
    if artifact_root_value is None:
        artifact_root = root / "artifacts" / "evidence"
    elif isinstance(artifact_root_value, str):
        artifact_root = _path(artifact_root_value, base=file_path.parent)
    else:
        raise ConfigError("Store artifact_root must be a path string")
    inline_limit = store_table.get("max_inline_bytes", 2048)
    store_page_limit = store_table.get("max_page_size", 50)
    if type(inline_limit) is not int or not 0 <= inline_limit <= 16384:
        raise ConfigError("Store max_inline_bytes must be between 0 and 16384")
    if type(store_page_limit) is not int or not 1 <= store_page_limit <= 100:
        raise ConfigError("Store max_page_size must be between 1 and 100")

    target_root_value = targets_table.get("root")
    if target_root_value is None:
        target_root = file_path.parent / "targets"
    elif isinstance(target_root_value, str):
        target_root = _path(target_root_value, base=file_path.parent)
    else:
        raise ConfigError("Target package root must be a path string")

    prefixes = secrets_table.get("allowed_env_prefixes", ["HACKBOT_SECRET_"])
    if (not isinstance(prefixes, list) or not prefixes or len(prefixes) > 16
            or any(not isinstance(prefix, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]*_", prefix)
                   for prefix in prefixes) or len(set(prefixes)) != len(prefixes)):
        raise ConfigError("Invalid allowed secret environment prefixes")
    references = secrets_table.get("references", {})
    if not isinstance(references, dict) or len(references) > 256:
        raise ConfigError("Invalid secret reference mapping")
    bindings = []
    kinds = {"PASSWORD", "COOKIE", "BEARER_TOKEN", "API_TOKEN", "LOGIN_DESCRIPTOR",
             "HEADER_SET", "SESSION_IMPORT_REFERENCE", "UNKNOWN"}
    for ref, raw_binding in references.items():
        if not isinstance(ref, str) or not re.fullmatch(
            r"(?:ref:)?[a-z][a-z0-9_-]{0,63}(?:/[a-z][a-z0-9_-]{0,63})?", ref
        ):
            raise ConfigError("Invalid opaque secret reference")
        binding = _table(raw_binding, frozenset({"provider_ref", "kind"}), "secret binding")
        provider_ref = binding.get("provider_ref")
        kind = binding.get("kind", "UNKNOWN")
        if (not isinstance(provider_ref, str)
                or not (re.fullmatch(r"env:[A-Z][A-Z0-9_]*", provider_ref)
                        or re.fullmatch(r"manual:[a-z][a-z0-9_-]{0,63}", provider_ref))):
            raise ConfigError("Invalid secret provider reference")
        if provider_ref.startswith("env:") and not any(
            provider_ref[4:].startswith(prefix) for prefix in prefixes
        ):
            raise ConfigError("Secret environment reference is outside allowed prefixes")
        if not isinstance(kind, str) or kind not in kinds:
            raise ConfigError("Invalid secret kind")
        bindings.append(SecretBindingConfig(ref, provider_ref, kind))

    profile_root_value = browser_table.get("profile_root")
    if profile_root_value is None:
        profile_root = root / "browser-profiles"
    elif isinstance(profile_root_value, str) and profile_root_value.strip() and ".." not in Path(profile_root_value).parts:
        candidate = Path(profile_root_value).expanduser()
        profile_root = candidate if candidate.is_absolute() else file_path.parent / candidate
        profile_root = profile_root.absolute()
    else:
        raise ConfigError("Invalid browser profile root")
    executable_value = browser_table.get("chromium_executable")
    if executable_value is None:
        executable = None
    elif isinstance(executable_value, str) and executable_value.startswith("/") and ".." not in Path(executable_value).parts:
        executable = Path(executable_value)
    else:
        raise ConfigError("Invalid Chromium executable path")
    browser_settings = BrowserSettings(
        profile_root=profile_root,
        display=browser_table.get("display"),
        vnc_url=browser_table.get("vnc_url"),
        chromium_executable=executable,
        max_sessions=browser_table.get("max_sessions", 20),
        max_page_size=browser_table.get("max_page_size", 50),
    )

    def burp_path(key: str, default: Path | None = None) -> Path | None:
        value = burp_table.get(key)
        if value is None:
            return default
        if not isinstance(value, str) or not value.startswith("/") or ".." in Path(value).parts:
            raise ConfigError("Invalid Burp path")
        return Path(value)

    project_root = burp_path("project_root", root / "artifacts" / "burp-projects")
    assert project_root is not None
    burp_settings = BurpSettings(
        enabled=burp_table.get("enabled", False),
        project_root=project_root,
        installation_jar=burp_path("installation_jar"),
        ca_certificate=burp_path("ca_certificate"),
        listener_start=burp_table.get("listener_start", 38080),
        listener_end=burp_table.get("listener_end", 38179),
        bridge_port=burp_table.get("bridge_port", 38777),
        bridge_secret_ref=burp_table.get("bridge_secret_ref"),
        max_event_bytes=burp_table.get("max_event_bytes", 1_048_576),
        max_inflight=burp_table.get("max_inflight", 8),
        third_party_capture=burp_table.get("third_party_capture", "DROP"),
    )

    return AppConfig(
        paths=LocalPaths(config_file=file_path, root=root),
        log_level=level.upper(),
        recon=ReconSettings(dsn_env, max_page_size, timeout),
        store=StoreSettings(artifact_root, inline_limit, store_page_limit),
        targets=TargetSettings(target_root),
        secrets=SecretSettings(tuple(prefixes), tuple(bindings)),
        browser=browser_settings,
        burp=burp_settings,
        executor=ExecutorSettings(**executor_table),
    )
