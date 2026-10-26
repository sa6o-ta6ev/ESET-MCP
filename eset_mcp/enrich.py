"""Fix up known quirks in ESET API responses before the agent sees them.

Each rule was checked against a real tenant (2026-10) before being added;
the counts in the comments come from that check. Rules only ever *add*
fields or fill obviously-empty ones, except the hash fix, which moves a
value into the field that matches its type. Original values are kept.

Rules:

- Version objects ``{id, name, major, minor, patch}``: outside patch
  management, ``id`` is "0" and major/minor/patch are all 0 - only ``name``
  ("13.3.1192.0") has the version (devices, installed applications,
  vulnerabilities: 1300+ objects). Fill major/minor/patch from ``name`` and
  add ``build`` (the 4th number, which no ESET field carries) so versions can
  be compared. Patch-management objects already have major/minor/patch
  (936/936 consistent with the packed ``id``); they only gain ``build``.
- Disk ``capacityBytes`` is reported in KiB, not bytes: every "512GB" SSD
  reports "500103168" (= 512.1 GB as KiB, 500 MB as bytes). Adds
  ``capacityGB`` (decimal GB); the raw field is left as ESET sent it.
- ``*HashSha1`` holding a 64-hex-char value (a SHA-256) while ``*HashSha256``
  is empty: v1 detections, 57 of 500. Move it, so hash lookups (VirusTotal,
  ...) use the right hash type. 40-char values are real SHA-1 and stay.
- Protobuf-style durations (``triageDuration: "339664.817892s"``): add
  ``<field>Human`` ("3d 22h 21m").
- ``description`` with literal ``\\n`` escapes instead of newlines (2 of 6
  incidents): unescape - but only when every backslash in the text belongs
  to such an escape, so Windows paths (``C:\\Users\\nick``) are never touched.
"""
from __future__ import annotations

import re
from typing import Any

_VERSION_KEYS = frozenset({"id", "name", "major", "minor", "patch"})
_VERSION_NAME = re.compile(r"^\s*v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?")
_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
_DURATION = re.compile(r"^(\d+(?:\.\d+)?)s$")
_ONLY_ESCAPES = re.compile(r"\\[nrt]")


def enrich(node: Any) -> Any:
    """Apply every rule recursively, in place; returns ``node`` for chaining."""
    if isinstance(node, dict):
        _fix_version(node)
        _fix_capacity(node)
        _fix_hashes(node)
        for key, value in list(node.items()):
            if isinstance(value, str):
                _fix_string_field(node, key, value)
            else:
                enrich(value)
    elif isinstance(node, list):
        for item in node:
            enrich(item)
    return node


def _fix_version(d: dict[str, Any]) -> None:
    if not _VERSION_KEYS <= d.keys():
        return
    m = _VERSION_NAME.match(str(d.get("name") or ""))
    if not m:
        return
    parts = [int(p) if p is not None else 0 for p in m.groups()]
    current = [_as_int(d.get(k)) for k in ("major", "minor", "patch")]
    if current == [0, 0, 0] and parts[:3] != [0, 0, 0]:
        d["major"], d["minor"], d["patch"] = parts[:3]
    if m.group(4) is not None and "build" not in d:
        d["build"] = parts[3]


def _fix_capacity(d: dict[str, Any]) -> None:
    raw = d.get("capacityBytes")
    kib = _as_int(raw)
    if kib > 0 and "capacityGB" not in d:
        d["capacityGB"] = round(kib * 1024 / 1e9, 1)


def _fix_hashes(d: dict[str, Any]) -> None:
    for key in [k for k in d if isinstance(k, str) and k.endswith("HashSha1")]:
        sha256_key = key[: -len("Sha1")] + "Sha256"
        value = d.get(key)
        if isinstance(value, str) and _HEX64.match(value) and not d.get(sha256_key):
            d[sha256_key] = value
            d[key] = ""


def _fix_string_field(d: dict[str, Any], key: str, value: str) -> None:
    if "duration" in key.lower():
        m = _DURATION.match(value)
        if m and f"{key}Human" not in d:
            d[f"{key}Human"] = _human_duration(float(m.group(1)))
    if key == "description" and "\\n" in value and "\n" not in value:
        if value.count("\\") == len(_ONLY_ESCAPES.findall(value)):
            d[key] = value.replace("\\n", "\n").replace("\\r", "\r").replace("\\t", "\t")


def _human_duration(seconds: float) -> str:
    total = round(seconds)
    if total < 60:
        return f"{total}s"
    days, rem = divmod(total, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    parts = [(days, "d"), (hours, "h"), (minutes, "m")] if days or hours else [(minutes, "m"), (secs, "s")]
    # Drop leading zero units, keep at most three.
    while parts and parts[0][0] == 0:
        parts.pop(0)
    return " ".join(f"{n}{u}" for n, u in parts[:3])


def _as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0
