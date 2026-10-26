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


CURRENT = {"ech": {"Settings": {"Proxy": {"Port": setting(3128), "Password": setting("WLu/j7qfjrQLDBjv4Q==")}}}}
OLDER = {"ech": {"Settings": {"Proxy": {"Port": setting(3128, ce_type=6)}}}}
CHANGELOG = {"changes": [{"change_id": "c1", "user_id": "u1", "timestamp": 1792591079,
                          "modified_parts": ["Proxy"], "orig_data": "1.ar.xz"}]}


def archive_policy() -> str:
    history = ar([
        ("1.ar.xz", lzma.compress(b"older settings", format=lzma.FORMAT_XZ)),
        ("info.json.lzma", lzma_alone(json.dumps(CHANGELOG))),
    ])
    archive = ar([
        ("ech.lzma", lzma_alone(json.dumps(CURRENT) + json.dumps(OLDER))),
        ("feature.Connectivity.lzma", lzma_alone(json.dumps({"Connectivity": {"Mode": setting(2)}}))),
        ("info.json", json.dumps({"written_by_ce": "12.1", "compatibility": ["ech>=1.0"]}).encode()),
        ("history.ar", history),
    ])
    return double_b64(b'{"policy":{"format":1}}\n' + archive)


# --- tests ---
def test_archive_format_decodes_all_members() -> None:
    d = decode_policy_data(archive_policy(), include_history=True)
    assert d["errors"] == []
    assert d["header"] == {"policy": {"format": 1}}
    assert d["info"]["written_by_ce"] == "12.1"
    # Long member name resolved through the GNU // table.
    assert {m["name"] for m in d["members"]} == {"ech.lzma", "feature.Connectivity.lzma", "info.json", "history.ar"}
    # Two documents (current + older product version), wrappers unwrapped incl. ce_type.
    current, older = d["settings"]["ech"]
    assert current["ech"]["Settings"]["Proxy"]["Port"] == 3128
    assert older["ech"]["Settings"]["Proxy"]["Port"] == 3128
    assert d["settings"]["feature.Connectivity"] == {"Connectivity": {"Mode": 2}}
    # Credentials are redacted.
    assert current["ech"]["Settings"]["Proxy"]["Password"] == REDACTED


def test_history_change_log_with_readable_times() -> None:
    full = decode_policy_data(archive_policy(), include_history=True)["history"]
    assert full["storedVersions"] == [{"name": "1.ar.xz", "bytes": full["storedVersions"][0]["bytes"]}]
    change = full["changeLog"]["changes"][0]
    assert change["time"] == "2026-10-21T13:57:59+00:00"
    summary = decode_policy_data(archive_policy())["history"]
    assert summary["storedVersions"] == 1 and summary["edits"] == 1


def test_raw_flags_keeps_wrappers_but_still_redacts() -> None:
    d = decode_policy_data(archive_policy(), raw_flags=True)
    current = d["settings"]["ech"][0]
    assert current["ech"]["Settings"]["Proxy"]["Port"] == {"ce_value": 3128, "ce_flags": 4}
    assert current["ech"]["Settings"]["Proxy"]["Password"]["ce_value"] == REDACTED


def test_format2_inline_settings() -> None:
    header = {"policy": {"format": 2, "written_by_ce": "2075.3", "data": {
        "efs_unix": {"ce_version_major": 10, "Settings": {"LiveGrid": {"LiveGridEnabled": setting(1, ce_type=6)}}}
    }}}
    raw = json.dumps(header).encode() + ar([("info.json", b'{"written_by_ce": "2075.3"}')])
    d = decode_policy_data(base64.b64encode(raw).decode())
    assert d["errors"] == []
    settings = d["settings"]["policy"]["policy"]["data"]["efs_unix"]
    assert settings["Settings"]["LiveGrid"]["LiveGridEnabled"] == 1
    assert settings["ce_version_major"] == 10  # sibling metadata is not a wrapper
    assert "data" not in d["header"]["policy"]


def test_plain_json_format() -> None:
    doc = {"policy": {"format": "1", "data": {"eesa": {"Settings": {"Enabled": setting(True)}}}}}
    d = decode_policy_data(double_b64(json.dumps(doc).encode()))
    assert d["errors"] == [] and d["members"] == []
    assert d["settings"]["settings"]["policy"]["data"]["eesa"]["Settings"]["Enabled"] is True


def test_compressed_flag_xz_payload() -> None:
    doc = {"policy": {"format": "1", "data": {"x": setting(1)}}}
    blob = base64.b64encode(lzma.compress(json.dumps(doc).encode(), format=lzma.FORMAT_XZ)).decode()
    d = decode_policy_data(blob, compressed=True)
    assert d["settings"]["settings"]["policy"]["data"]["x"] == 1


def test_not_base64_raises() -> None:
    with pytest.raises(PolicyDecodeError):
        decode_policy_data("{not base64}")


def test_bad_member_is_reported_not_fatal() -> None:
    archive = ar([("ech.lzma", b"not lzma at all"), ("info.json", b'{"a": 1}')])
    d = decode_policy_data(base64.b64encode(b'{"policy":{"format":1}}' + archive).decode())
    assert d["info"] == {"a": 1}
    assert any("ech.lzma" in e for e in d["errors"])


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
