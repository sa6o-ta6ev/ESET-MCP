"""Policy settings decoding (no network).

Fixtures are synthetic but built to the layouts observed in a real tenant
(2026-10): archive format with GNU long names and history, format 2 with
inline settings, and plain JSON.
"""
from __future__ import annotations

import base64
import json
import lzma

import pytest

from eset_mcp.policy_decode import (
    REDACTED,
    PolicyDecodeError,
    decode_policy_data,
    find_policy_data,
    omit_policy_blobs,
    outline,
    parse_ar,
    search_settings,
    select_path,
    simplify,
)

POLICY_TYPE = "type.googleapis.com/Era.Common.DataDefinition.Policy.PolicyData"


# --- fixture builders ---
def ar(members: list[tuple[str, bytes]]) -> bytes:
    """Build a GNU ar archive; names over 15 chars go to the // table."""
    table = b""
    entries = []
    for name, data in members:
        if len(name) + 1 > 16:
            ref = f"/{len(table)}"
            table += f"{name}/\n".encode()
            entries.append((ref, data))
        else:
            entries.append((f"{name}/", data))
    if table:
        entries.insert(0, ("//", table))
    out = b"!<arch>\n"
    for name, data in entries:
        header = f"{name:<16}{0:<12}{0:<6}{0:<6}{100644:<8}{len(data):<10}`\n".encode()
        assert len(header) == 60
        out += header + data + (b"\n" if len(data) % 2 else b"")
    return out


def lzma_alone(text: str) -> bytes:
    return lzma.compress(text.encode(), format=lzma.FORMAT_ALONE)


def double_b64(raw: bytes) -> str:
    return base64.b64encode(base64.b64encode(raw)).decode()


def setting(value, flags=4, ce_type=None):
    out = {"ce_value": value, "ce_flags": flags}
    if ce_type is not None:
        out["ce_type"] = ce_type
    return out


# Archive variant: {"policy": {"product", "version", "data": <settings>}}, no product wrapper.
CURRENT = {"policy": {"product": "ech", "version": "4.2.0", "data": {
    "Settings": {"Proxy": {"Port": setting(3128), "Password": setting("WLu/j7qfjrQLDBjv4Q==")}}}}}
OLDER = {"policy": {"product": "ech", "version": "1.0.0", "data": {
    "Settings": {"Proxy": {"Port": setting(3128, ce_type=6)}}}}}
FEATURE = {"policy": {"feature": "Connectivity", "version": "1.0", "data": {"Mode": setting(2)}}}
CHANGELOG = {"changes": [{"change_id": "c1", "user_id": "u1", "timestamp": 1792591079,
                          "modified_parts": ["Proxy"], "orig_data": "1.ar.xz"}]}


def archive_policy() -> str:
    history = ar([
        ("1.ar.xz", lzma.compress(b"older settings", format=lzma.FORMAT_XZ)),
        ("info.json.lzma", lzma_alone(json.dumps(CHANGELOG))),
    ])
    archive = ar([
        ("ech.lzma", lzma_alone(json.dumps(CURRENT) + json.dumps(OLDER))),
        ("feature.Connectivity.lzma", lzma_alone(json.dumps(FEATURE))),
        ("info.json", json.dumps({"written_by_ce": "12.1", "compatibility": ["ech>=1.0"]}).encode()),
        ("history.ar", history),
    ])
    return double_b64(b'{"policy":{"format":1}}\n' + archive)


# --- tests ---
def test_archive_format_decodes_all_members() -> None:
    d = decode_policy_data(archive_policy(), include_history=True)
    assert d["errors"] == []
    assert d["format"] == "archive"
    assert d["info"]["written_by_ce"] == "12.1"
    # Long member name resolved through the GNU // table.
    assert {m["name"] for m in d["members"]} == {"ech.lzma", "feature.Connectivity.lzma", "info.json", "history.ar"}
    # Two documents (current + older product version), wrappers unwrapped incl. ce_type.
    current, older, feature = d["documents"]
    assert (current["source"], current["target"], current["version"]) == ("ech.lzma", "ech", "4.2.0")
    assert older["version"] == "1.0.0"
    assert current["settings"]["Settings"]["Proxy"]["Port"] == 3128
    assert older["settings"]["Settings"]["Proxy"]["Port"] == 3128
    assert (feature["target"], feature["settings"]) == ("Connectivity", {"Mode": 2})
    # Credentials are redacted.
    assert current["settings"]["Settings"]["Proxy"]["Password"] == REDACTED


def test_history_change_log_with_readable_times() -> None:
    full = decode_policy_data(archive_policy(), include_history=True)["history"]
    assert full["storedVersions"] == [{"name": "1.ar.xz", "bytes": full["storedVersions"][0]["bytes"]}]
    change = full["changeLog"]["changes"][0]
    assert change["time"] == "2026-10-21T13:57:59+00:00"
    summary = decode_policy_data(archive_policy())["history"]
    assert summary["storedVersions"] == 1 and summary["edits"] == 1


def test_raw_flags_keeps_wrappers_but_still_redacts() -> None:
    d = decode_policy_data(archive_policy(), raw_flags=True)
    proxy = d["documents"][0]["settings"]["Settings"]["Proxy"]
    assert proxy["Port"] == {"ce_value": 3128, "ce_flags": 4}
    assert proxy["Password"]["ce_value"] == REDACTED


def test_format2_inline_settings() -> None:
    header = {"policy": {"format": 2, "written_by_ce": "2075.3", "data": {
        "efs_unix": {"ce_version_major": 10, "Settings": {"LiveGrid": {"LiveGridEnabled": setting(1, ce_type=6)}}}
    }}}
    raw = json.dumps(header).encode() + ar([("info.json", b'{"written_by_ce": "2075.3"}')])
    d = decode_policy_data(base64.b64encode(raw).decode())
    assert d["errors"] == [] and d["format"] == "inline"
    [doc] = d["documents"]
    # Product wrapper removed, version taken from ce_version_*: same shape as archive.
    assert (doc["source"], doc["target"], doc["version"]) == ("inline", "efs_unix", "10")
    assert doc["meta"] == {"format": 2, "written_by_ce": "2075.3"}
    assert doc["settings"] == {"Settings": {"LiveGrid": {"LiveGridEnabled": 1}}}


def test_plain_json_format() -> None:
    doc = {"policy": {"format": "1", "version_major": "8", "version_minor": "1", "version_build": "2",
                      "data": {"eesa": {"Settings": {"Enabled": setting(True)}}}}}
    d = decode_policy_data(double_b64(json.dumps(doc).encode()))
    assert d["errors"] == [] and d["members"] == [] and d["format"] == "plain"
    [out] = d["documents"]
    assert (out["source"], out["target"], out["version"]) == ("plain", "eesa", "8.1.2")
    assert out["settings"] == {"Settings": {"Enabled": True}}


def test_compressed_flag_xz_payload() -> None:
    doc = {"policy": {"format": "1", "data": {"x": {"Enabled": setting(1)}}}}
    blob = base64.b64encode(lzma.compress(json.dumps(doc).encode(), format=lzma.FORMAT_XZ)).decode()
    d = decode_policy_data(blob, compressed=True)
    assert d["documents"][0]["settings"] == {"Enabled": 1}


def test_not_base64_raises() -> None:
    with pytest.raises(PolicyDecodeError):
        decode_policy_data("{not base64}")


def test_bad_member_is_reported_not_fatal() -> None:
    archive = ar([("ech.lzma", b"not lzma at all"), ("info.json", b'{"a": 1}')])
    d = decode_policy_data(base64.b64encode(b'{"policy":{"format":1}}' + archive).decode())
    assert d["info"] == {"a": 1}
    assert any("ech.lzma" in e for e in d["errors"])


def test_all_variants_give_the_same_document_shape() -> None:
    plain = {"policy": {"format": "1", "data": {"ech": {"Settings": {"Proxy": {"Port": setting(3128)}}}}}}
    inline = json.dumps({"policy": {"format": 2, "data": {"ech": {"Settings": {"Proxy": {"Port": setting(3128)}}}}}})
    variants = [
        decode_policy_data(archive_policy()),
        decode_policy_data(double_b64(json.dumps(plain).encode())),
        decode_policy_data(base64.b64encode(inline.encode() + ar([("info.json", b"{}")])).decode()),
    ]
    for d in variants:
        doc = d["documents"][0]
        assert set(doc) == {"source", "target", "version", "meta", "settings"}
        assert doc["target"] == "ech"
        # Same setting, same path, whatever the storage variant.
        assert select_path(doc["settings"], "Settings.Proxy.Port") == 3128


def test_parse_ar_bsd_long_names() -> None:
    name = b"feature.Connectivity.lzma"
    data = name + b"payload"
    header = f"{'#1/' + str(len(name)):<16}{0:<12}{0:<6}{0:<6}{100644:<8}{len(data):<10}`\n".encode()
    [member] = parse_ar(b"!<arch>\n" + header + data + (b"\n" if len(data) % 2 else b""))
    assert member.name == "feature.Connectivity.lzma" and member.data == b"payload"


def test_search_select_and_outline() -> None:
    doc = simplify({"Settings": {"Firewall": {"Enabled": setting(True), "Rules": [{"name": "allow dns"}]},
                                 "Proxy": {"Host": setting("proxy.local")}}})
    hits = search_settings(doc, "firewall")
    assert hits == [{"path": "Settings.Firewall", "section": ["Enabled", "Rules"]}]
    assert search_settings(doc, "proxy.local") == [{"path": "Settings.Proxy.Host", "value": "proxy.local"}]
    assert search_settings(doc, "dns") == [{"path": "Settings.Firewall.Rules[0].name", "value": "allow dns"}]
    assert select_path(doc, "Settings.Firewall.Rules[0].name") == "allow dns"
    assert select_path(doc, "Settings.Missing") is None
    assert outline(doc, depth=2) == {"Settings": {"Firewall": "{2 keys}", "Proxy": "{1 keys}"}}


def test_find_and_omit_policy_blobs() -> None:
    policy = {"policy": {"uuid": "p1", "configuration": {"@type": POLICY_TYPE, "data": "QUJD" * 10, "product": "x"}}}
    assert len(find_policy_data(policy)) == 1
    omitted = omit_policy_blobs(policy, "use policy_settings")
    assert omitted["policy"]["configuration"]["data"].startswith("[40 chars of encoded settings omitted")
    assert omitted["policy"]["uuid"] == "p1"
    # Unrelated "data" keys are untouched.
    assert omit_policy_blobs({"data": "x"}, "h") == {"data": "x"}
