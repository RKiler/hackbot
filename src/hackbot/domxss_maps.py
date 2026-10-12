"""Bounded source-map references and original-location resolution."""

from __future__ import annotations

from dataclasses import dataclass
from importlib.resources import as_file, files
import json
import re
import subprocess
from urllib.parse import urljoin, urlsplit

from .domxss_static import SourceLocation


MAX_SOURCE_MAP_BYTES = 1_048_576
_REFERENCE = re.compile(rb"(?:\/\/[#@]|\/\*[#@])\s*sourceMappingURL=([^\s*]+)")


@dataclass(frozen=True, slots=True)
class MappedSourceLocation:
    source: str
    line: int
    column: int


def referenced_source_map(js_url: str, js_body: bytes) -> str | None:
    """Return only a directly referenced HTTP(S) map URL; scope is checked separately."""
    if not isinstance(js_body, bytes):
        raise ValueError("Invalid JavaScript body")
    matches = _REFERENCE.findall(js_body[-8192:])
    if not matches:
        return None
    try:
        reference = matches[-1].decode("utf-8")
        if not 1 <= len(reference) <= 2048 or reference.lower().startswith("data:"):
            return None
        resolved = urljoin(js_url, reference)
        parsed = urlsplit(resolved)
    except (UnicodeDecodeError, ValueError):
        return None
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname
            or parsed.username or parsed.password or parsed.fragment):
        return None
    return resolved


def map_locations(body: bytes, locations: tuple[SourceLocation, ...], *,
                  node_binary: str = "node") -> tuple[MappedSourceLocation | None, ...]:
    if not isinstance(body, bytes) or len(body) > MAX_SOURCE_MAP_BYTES:
        raise ValueError("Source map exceeds limit")
    if len(locations) > 32 or any(not isinstance(item, SourceLocation) for item in locations):
        raise ValueError("Invalid source-map positions")
    try:
        parsed = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Malformed source map") from exc
    if (not isinstance(parsed, dict) or parsed.get("version") != 3
            or not isinstance(parsed.get("mappings"), str)
            or not isinstance(parsed.get("sources"), list)
            or len(parsed["sources"]) > 10000):
        raise ValueError("Unsupported source map")
    # sourcesContent is deliberately excluded from the parser subprocess and metadata.
    minimal = {key: parsed[key] for key in ("version", "mappings", "sources", "names", "sourceRoot")
               if key in parsed}
    request = {"map": minimal,
               "positions": [{"line": item.line, "column": item.column} for item in locations]}
    try:
        helper = files("hackbot").joinpath("dom_map.cjs")
        with as_file(helper) as helper_path:
            process = subprocess.run(
                [node_binary, "--max-old-space-size=128", str(helper_path)],
                input=json.dumps(request, separators=(",", ":")).encode(),
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                timeout=5, check=False,
            )
        if process.returncode != 0 or len(process.stdout) > 16_384:
            raise ValueError("Source-map parser unavailable")
        result = json.loads(process.stdout)
    except (OSError, subprocess.TimeoutExpired, UnicodeDecodeError,
            json.JSONDecodeError) as exc:
        raise ValueError("Source-map parser unavailable") from exc
    positions = result.get("positions") if isinstance(result, dict) else None
    if not isinstance(positions, list) or len(positions) != len(locations):
        raise ValueError("Source-map lookup failed")
    mapped: list[MappedSourceLocation | None] = []
    for item in positions:
        if item is None:
            mapped.append(None)
        elif (isinstance(item, dict) and isinstance(item.get("source"), str)
              and 1 <= len(item["source"]) <= 512 and "\x00" not in item["source"]
              and type(item.get("line")) is int and item["line"] >= 1
              and type(item.get("column")) is int and item["column"] >= 1):
            mapped.append(MappedSourceLocation(item["source"], item["line"], item["column"]))
        else:
            raise ValueError("Invalid mapped source location")
    return tuple(mapped)
