"""Local-only, typed Phase 1 configuration."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
import tomllib
from typing import Mapping


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

    top = _table(data, frozenset({"paths", "logging", "recon", "store"}), "top-level")
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

    return AppConfig(
        paths=LocalPaths(config_file=file_path, root=root),
        log_level=level.upper(),
        recon=ReconSettings(dsn_env, max_page_size, timeout),
        store=StoreSettings(artifact_root, inline_limit, store_page_limit),
    )
