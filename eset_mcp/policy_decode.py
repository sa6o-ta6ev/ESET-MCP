"""Decode ESET policy settings ("PolicyData" blobs) into plain JSON.

ESET returns a policy's settings as one opaque string inside the policy
object::

    "configuration": {
      "@type": "type.googleapis.com/Era.Common.DataDefinition.Policy.PolicyData",
      "data": "ZXlKd2IyeHBZM2tpT25z...",
      "product": "eset.local.products.ech",
      "compressed": false
    }

The format is not documented by ESET. Observed layout (2026-10, ESET Connect):

1. ``data`` is base64 - usually twice (the inner layer is itself base64 text).
2. The decoded bytes are a one-line JSON header (``{"policy":{"format":1}}``)
   followed by a Unix ``ar`` archive (``!<arch>\\n``). Member names longer
   than 16 characters use the GNU long-name table (member ``//``, names
   ``/<offset>``).
3. Members:
   - ``<product>.lzma`` / ``feature.<name>.lzma`` - the settings, legacy
     ".lzma" (LZMA-alone) compressed. The payload is one or more JSON
     documents back to back (the same settings written for the current and
     for older product versions).
   - ``info.json`` - which console version wrote the policy and which product
     versions it is compatible with.
   - ``history.ar`` - a nested ar archive: ``N.ar.xz`` (earlier versions of
     the settings, xz) and ``info.json.lzma`` (change log: user, timestamp,
     changed section per edit).
4. Each setting is wrapped as ``{"ce_value": <value>, "ce_flags": <int>}``,
   sometimes with ``"ce_type"`` too. :func:`simplify` unwraps those to the
   bare value.

Every variant is normalised to the same ``documents`` list (see
:func:`decode_policy_data`), so callers never see which one was stored.

Variants seen in one tenant's 84 policies:

- archive format (above) - settings in ``*.lzma`` members, often with history;
- format 2 - settings inline in the header (``{"policy": {"format": 2,
  "data": {...}}}``), archive carries only ``info.json``;
- plain - no archive at all, the decoded bytes are the settings JSON
  (``{"policy": {"format": "1", ...}}``).

Everything here is defensive: an unexpected layer is reported in ``errors``
instead of failing the whole decode, so a format change degrades to
"partially decoded" rather than "no answer".
"""
from __future__ import annotations

import base64
import binascii
import datetime as _dt
import gzip
import json
import lzma
import re
import zlib
from dataclasses import dataclass
from typing import Any

_AR_MAGIC = b"!<arch>\n"
_AR_HEADER_LEN = 60
_MAX_BASE64_LAYERS = 5
_BASE64_TEXT = re.compile(rb"^[A-Za-z0-9+/=_\-\r\n]+$")

# Settings whose name suggests a credential. ESET stores them encrypted or
# obfuscated, so they are useless for analysis - and not worth putting in an
# LLM context either.
_SECRET_KEY = re.compile(r"pass(word|wd)?$|secret|token|credential|private.?key", re.IGNORECASE)
REDACTED = "[redacted]"


@dataclass
class ArMember:
    name: str
    data: bytes


class PolicyDecodeError(Exception):
    """The blob could not be decoded at all."""


# --- Public API ---
def find_policy_data(obj: Any) -> list[dict[str, Any]]:
    """Return every PolicyData container (``{"@type": ...PolicyData, "data": str}``) in ``obj``."""
    found: list[dict[str, Any]] = []
    if isinstance(obj, dict):
        if isinstance(obj.get("data"), str) and "PolicyData" in str(obj.get("@type", "")):
            found.append(obj)
        for value in obj.values():
            found.extend(find_policy_data(value))
    elif isinstance(obj, list):
        for item in obj:
            found.extend(find_policy_data(item))
    return found


def omit_policy_blobs(obj: Any, hint: str) -> Any:
    """Copy of ``obj`` with every PolicyData ``data`` string replaced by a short note."""
    if isinstance(obj, dict):
        out = {}
        for key, value in obj.items():
            if key == "data" and isinstance(value, str) and "PolicyData" in str(obj.get("@type", "")):
                out[key] = f"[{len(value)} chars of encoded settings omitted - {hint}]"
            else:
                out[key] = omit_policy_blobs(value, hint)
        return out
    if isinstance(obj, list):
        return [omit_policy_blobs(item, hint) for item in obj]
    return obj


def decode_policy_data(
    data: str,
    *,
    compressed: bool = False,
    include_history: bool = False,
    raw_flags: bool = False,
) -> dict[str, Any]:
    """Decode one PolicyData ``data`` string.

    Returns ``{"format", "documents", "info", "history", "members", "errors"}``.

    ``documents`` has the same shape whatever the storage variant - one entry
    per settings document::

        {"source": "endpoint.lzma" | "inline" | "plain",
         "target": "endpoint" | "feature.Connectivity" | ...,   # product or feature
         "version": "10.1.2045.0" | None,                       # product version
         "meta": {...} | None,                                  # format, written_by_ce, ...
         "settings": {"Settings": {...}, ...}}                  # the settings tree

    The product-level wrapper some variants add inside ``data`` is removed,
    so the same setting has the same path in every variant. ``ce_value``
    wrappers are unwrapped unless ``raw_flags``; credentials are redacted.

    ``history``: change log + stored earlier versions when
    ``include_history``; otherwise just how many edits/versions exist
    (archive variant only).

    Raises :class:`PolicyDecodeError` only when not even the outer layers
    decode.
    """
    errors: list[str] = []
    raw = _strip_base64_layers(data)
    if compressed or not (raw.lstrip().startswith(b"{") or _AR_MAGIC in raw[:4096]):
        raw = _decompress_unknown(raw)

    ar_at = raw.find(_AR_MAGIC)
    prefix = raw if ar_at < 0 else raw[:ar_at]
    header_docs = _json_documents(prefix, errors, "header")
    header = header_docs[0] if len(header_docs) == 1 else None

    result: dict[str, Any] = {
        "format": None,
        "documents": [],
        "info": None,
        "history": None,
        "members": [],
        "errors": errors,
    }
    if ar_at < 0:
        # No archive: the payload itself is the settings JSON.
        result["format"] = "plain"
        result["documents"] = _to_documents("plain", header_docs, raw_flags)
        if not result["documents"]:
            errors.append("no settings found in the decoded policy data")
        return result

    result["format"] = "archive"
    for member in parse_ar(raw[ar_at:]):
        result["members"].append({"name": member.name, "bytes": len(member.data)})
        name = member.name.lower()
        try:
            if name.endswith(".lzma"):
                docs = _json_documents(_decompress_lzma_alone(member.data), errors, member.name)
                result["documents"].extend(_to_documents(member.name, docs, raw_flags))
            elif name == "info.json":
                docs = _json_documents(member.data, errors, member.name)
                result["info"] = docs[0] if len(docs) == 1 else docs
            elif name == "history.ar":
                result["history"] = _decode_history(member.data, include_history, errors)
        except (lzma.LZMAError, ValueError, EOFError) as e:
            errors.append(f"{member.name}: {type(e).__name__}: {e}")
    if not result["documents"] and _inline_settings(header):
        # Format 2: the settings live in the header document itself
        # ({"policy": {"format": 2, "data": {...}}}) and the archive only
        # carries info.json.
        result["format"] = "inline"
        result["documents"] = _to_documents("inline", [header], raw_flags)
    if not result["documents"]:
        errors.append("no settings found (no *.lzma member and no inline policy data)")
    return result


_VERSION_PARTS = ("version_major", "version_minor", "version_build")
_CE_VERSION_PARTS = ("ce_version_major", "ce_version_minor", "ce_version_build")


def _to_documents(source: str, docs: list[Any], raw_flags: bool) -> list[dict[str, Any]]:
    """Normalise raw settings documents to the common ``documents`` shape."""
    out = []
    for doc in docs:
        policy = doc.get("policy") if isinstance(doc, dict) else None
        if not isinstance(policy, dict) or not isinstance(policy.get("data"), dict):
            # Unknown layout - pass it through rather than guess.
            out.append({"source": source, "target": None, "version": None, "meta": None,
                        "settings": _finish_tree(doc, raw_flags)})
            continue
        tree = policy["data"]
        target = policy.get("product") or policy.get("feature")
        version = policy.get("version") or _join_version(policy, _VERSION_PARTS)
        # Plain/inline variants wrap the settings in one product-level key
        # ({"endpoint": {"ce_version_major": ..., "Settings": {...}}}); the
        # archive variant does not. Unwrap so paths match across variants.
        if "format" in policy and len(tree) == 1:
            (key, inner), = tree.items()
            if isinstance(inner, dict):
                target = target or key
                version = version or _join_version(inner, _CE_VERSION_PARTS)
                tree = {k: v for k, v in inner.items() if k not in _CE_VERSION_PARTS}
        meta = {k: v for k, v in policy.items()
                if k not in ("data", "product", "feature", "version", *_VERSION_PARTS)}
        out.append({
            "source": source,
            "target": target,
            "version": str(version) if version not in (None, "") else None,
            "meta": meta or None,
            "settings": _finish_tree(tree, raw_flags),
        })
    return out


def _join_version(obj: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    parts = [simplify(obj[k]) for k in keys if k in obj]
    return ".".join(str(p) for p in parts) if parts else None


def _inline_settings(header: Any) -> bool:
    return (
        isinstance(header, dict)
        and isinstance(header.get("policy"), dict)
        and isinstance(header["policy"].get("data"), dict)
    )


def simplify(node: Any) -> Any:
    """Unwrap ``{"ce_value": v, "ce_flags": f[, "ce_type": t]}`` to ``v``, recursively.

    Only objects made purely of ``ce_*`` keys are setting wrappers; sibling
    metadata such as ``ce_version_major`` next to real settings is kept.
    """
    if isinstance(node, dict):
        if "ce_value" in node and all(str(k).startswith("ce_") for k in node):
            return simplify(node["ce_value"])
        return {k: simplify(v) for k, v in node.items()}
    if isinstance(node, list):
        return [simplify(item) for item in node]
    return node


def redact_secrets(node: Any) -> Any:
    """Replace values of credential-looking keys with ``[redacted]``."""
    if isinstance(node, dict):
        out = {}
        for key, value in node.items():
            if _SECRET_KEY.search(str(key)) and not isinstance(value, (dict, list)) and value not in ("", None):
                out[key] = REDACTED
            elif _SECRET_KEY.search(str(key)) and isinstance(value, dict) and "ce_value" in value:
                out[key] = {**value, "ce_value": REDACTED}
            else:
                out[key] = redact_secrets(value)
        return out
    if isinstance(node, list):
        return [redact_secrets(item) for item in node]
    return node


def search_settings(node: Any, needle: str, limit: int = 100) -> list[dict[str, Any]]:
    """Case-insensitive substring search over setting names and scalar values.

    A matching *section* (a key whose value is an object or list) is reported
    once with its keys, not expanded - fetch it with ``path`` if needed.
    """
    needle_l = needle.lower()
    hits: list[dict[str, Any]] = []

    def walk(value: Any, path: str) -> None:
        if len(hits) >= limit:
            return
        if isinstance(value, dict):
            for key, item in value.items():
                if len(hits) >= limit:
                    return
                child = f"{path}.{key}" if path else str(key)
                if needle_l in str(key).lower():
                    if isinstance(item, dict):
                        hits.append({"path": child, "section": sorted(item)[:30]})
                    elif isinstance(item, list):
                        hits.append({"path": child, "section": f"[{len(item)} items]"})
                    else:
                        hits.append({"path": child, "value": item})
                    continue
                walk(item, child)
        elif isinstance(value, list):
            for i, item in enumerate(value):
                walk(item, f"{path}[{i}]")
        elif needle_l in str(value).lower():
            hits.append({"path": path, "value": value})

    walk(node, "")
    return hits


def select_path(node: Any, path: str) -> Any:
    """Follow a dotted path (``a.b.c``, ``list[0]`` allowed); returns None if absent."""
    current = node
    for part in filter(None, path.split(".")):
        match = re.fullmatch(r"(.*?)((?:\[\d+\])*)", part)
        key, indexes = match.group(1), match.group(2)
        if key:
            if not isinstance(current, dict) or key not in current:
                return None
            current = current[key]
        for index in re.findall(r"\[(\d+)\]", indexes):
            if not isinstance(current, list) or int(index) >= len(current):
                return None
            current = current[int(index)]
    return current


def outline(node: Any, depth: int = 2) -> Any:
    """Key structure of ``node`` down to ``depth`` levels, for oversized results."""
    if isinstance(node, dict):
        if depth <= 0:
            return f"{{{len(node)} keys}}"
        return {k: outline(v, depth - 1) for k, v in node.items()}
    if isinstance(node, list):
        return f"[{len(node)} items]"
    return type(node).__name__


def parse_ar(blob: bytes) -> list[ArMember]:
    """Parse a Unix ar archive, including GNU (``//`` table) and BSD (``#1/N``) long names."""
    if not blob.startswith(_AR_MAGIC):
        raise ValueError("not an ar archive")
    members: list[ArMember] = []
    long_names = b""
    pos = len(_AR_MAGIC)
    while pos + _AR_HEADER_LEN <= len(blob):
        header = blob[pos:pos + _AR_HEADER_LEN]
        if header[58:60] != b"`\n":
            raise ValueError(f"bad ar member header at offset {pos}")
        raw_name = header[0:16].decode("ascii", "replace").rstrip()
        size = int(header[48:58].decode("ascii").strip() or 0)
        data = blob[pos + _AR_HEADER_LEN:pos + _AR_HEADER_LEN + size]
        pos += _AR_HEADER_LEN + size + (size % 2)  # members are 2-byte aligned

        if raw_name == "//":  # GNU long-name table
            long_names = data
            continue
        if raw_name in ("/", "/SYM64/"):  # symbol tables
            continue
        if raw_name.startswith("/") and raw_name[1:].isdigit():  # GNU long name
            offset = int(raw_name[1:])
            end = long_names.find(b"\n", offset)
            name = long_names[offset:end if end >= 0 else None].decode("utf-8", "replace")
        elif raw_name.startswith("#1/") and raw_name[3:].isdigit():  # BSD long name
            name_len = int(raw_name[3:])
            name = data[:name_len].decode("utf-8", "replace").rstrip("\x00")
            data = data[name_len:]
        else:
            name = raw_name
        members.append(ArMember(name=name.rstrip("/"), data=data))
    return members


# --- Internals ---
def _strip_base64_layers(data: str) -> bytes:
    current = data.strip().encode("ascii", "replace")
    decoded_any = False
    for _ in range(_MAX_BASE64_LAYERS):
        if not _BASE64_TEXT.fullmatch(current):
            break
        try:
            compact = re.sub(rb"\s", b"", current).replace(b"-", b"+").replace(b"_", b"/")
            current = base64.b64decode(compact + b"=" * (-len(compact) % 4), validate=True)
            decoded_any = True
        except (binascii.Error, ValueError):
            break
        current = current.strip()
    if not decoded_any:
        raise PolicyDecodeError("policy data is not base64")
    return current


def _decompress_unknown(blob: bytes) -> bytes:
    """Undo a compression layer when ``compressed`` is set (format not documented)."""
    attempts = (
        (b"\xfd7zXZ\x00", lambda b: lzma.decompress(b, format=lzma.FORMAT_XZ)),
        (b"\x1f\x8b", gzip.decompress),
        (b"\x5d\x00", lambda b: lzma.decompress(b, format=lzma.FORMAT_ALONE)),
        (b"\x78", zlib.decompress),
    )
    for magic, fn in attempts:
        if blob.startswith(magic):
            try:
                return fn(blob)
            except (lzma.LZMAError, OSError, zlib.error, EOFError) as e:
                raise PolicyDecodeError(f"compressed policy data could not be unpacked: {e}") from e
    return blob


def _decompress_lzma_alone(blob: bytes) -> bytes:
    try:
        return lzma.decompress(blob, format=lzma.FORMAT_ALONE)
    except lzma.LZMAError:
        return lzma.decompress(blob)  # fall back to auto-detect (xz)


def _json_documents(blob: bytes, errors: list[str], where: str) -> list[Any]:
    """Parse one or more JSON documents written back to back."""
    text = blob.decode("utf-8", "replace").lstrip("﻿")
    decoder = json.JSONDecoder()
    docs: list[Any] = []
    pos = 0
    while True:
        while pos < len(text) and text[pos] in " \t\r\n\x00":
            pos += 1
        if pos >= len(text):
            break
        try:
            doc, pos = decoder.raw_decode(text, pos)
        except json.JSONDecodeError as e:
            errors.append(f"{where}: {len(text) - pos} trailing bytes are not JSON ({e.msg})")
            break
        docs.append(doc)
    return docs


def _finish_tree(tree: Any, raw_flags: bool) -> Any:
    tree = redact_secrets(tree)
    return tree if raw_flags else simplify(tree)


def _decode_history(blob: bytes, include: bool, errors: list[str]) -> dict[str, Any]:
    members = parse_ar(blob)
    versions = [m for m in members if m.name.lower().endswith(".xz")]
    changelog: Any = None
    for m in members:
        if m.name.lower().startswith("info.json"):
            payload = _decompress_lzma_alone(m.data) if m.name.lower().endswith(".lzma") else m.data
            docs = _json_documents(payload, errors, f"history/{m.name}")
            changelog = docs[0] if len(docs) == 1 else docs
    edits = _count_edits(changelog)
    _add_readable_times(changelog)
    if not include:
        return {"storedVersions": len(versions), "edits": edits, "hint": "pass include_history=true for the change log"}
    return {
        "storedVersions": [{"name": m.name, "bytes": len(m.data)} for m in versions],
        "changeLog": changelog,
    }


def _add_readable_times(changelog: Any) -> None:
    """Make change-log entries readable, in place.

    Entries look like ``{"change_id", "user_id", "timestamp", "modified_parts",
    "orig_data"}``. Adds ``time`` (ISO 8601, UTC) next to the Unix
    ``timestamp``, and splits ``user_id`` - observed as
    ``"<uuid>;PR;PW;SR;SW;"`` or ``"<uuid>;PR;PW;-;-;"`` - into ``user`` and
    ``userFlags`` (``-`` placeholders dropped). The flags are undocumented;
    they look like read/write permissions of the editing user.
    """
    entries = changelog.get("changes") if isinstance(changelog, dict) else changelog
    if not isinstance(entries, list):
        return
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        ts = entry.get("timestamp")
        if isinstance(ts, (int, float)) and 0 < ts < 1e11:
            entry["time"] = _dt.datetime.fromtimestamp(ts, _dt.UTC).isoformat(timespec="seconds")
        user_id = entry.get("user_id")
        if isinstance(user_id, str) and ";" in user_id:
            user, *flags = user_id.split(";")
            entry["user"] = user
            entry["userFlags"] = [f for f in flags if f and f != "-"]


def _count_edits(changelog: Any) -> int | None:
    if isinstance(changelog, list):
        return len(changelog)
    if isinstance(changelog, dict):
        lists = [v for v in changelog.values() if isinstance(v, list)]
        if len(lists) == 1:
            return len(lists[0])
    return None
