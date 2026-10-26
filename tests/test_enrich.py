"""Response enrichment rules (no network). Shapes mirror real ESET responses."""
from __future__ import annotations

from eset_mcp.enrich import enrich

SHA1 = "a" * 40
SHA256 = "b" * 64


def test_version_filled_from_name_when_fields_are_zero() -> None:
    device = {"version": {"id": "0", "name": "13.3.1192.0", "major": 0, "minor": 0, "patch": 0}}
    enrich(device)
    assert device["version"] == {"id": "0", "name": "13.3.1192.0", "major": 13, "minor": 3,
                                 "patch": 1192, "build": 0}


def test_patch_version_already_set_only_gains_build() -> None:
    # Patch management: major/minor/patch match the packed id; build is lost there.
    v = {"id": str(154 << 48 | 0 << 32 | 8037 << 16), "name": "154.0.8037.93",
         "major": 154, "minor": 0, "patch": 8037}
    enrich(v)
    assert (v["major"], v["minor"], v["patch"], v["build"]) == (154, 0, 8037, 93)


def test_version_with_non_numeric_name_is_left_alone() -> None:
    v = {"id": "0", "name": "unknown", "major": 0, "minor": 0, "patch": 0}
    enrich(v)
    assert v == {"id": "0", "name": "unknown", "major": 0, "minor": 0, "patch": 0}


def test_disk_capacity_reported_in_kib_gets_gb() -> None:
    disks = [{"displayName": "AirDisk 512GB SSD", "capacityBytes": "500103168"},
             {"displayName": "DVD drive", "capacityBytes": "0"}]
    enrich(disks)
    assert disks[0]["capacityGB"] == 512.1
    assert disks[0]["capacityBytes"] == "500103168"  # raw value kept
    assert "capacityGB" not in disks[1]


def test_sha256_in_sha1_field_is_moved() -> None:
    misplaced = {"objectHashSha1": SHA256, "objectHashSha256": ""}
    real_sha1 = {"objectHashSha1": SHA1, "objectHashSha256": ""}
    enrich([misplaced, real_sha1])
    assert misplaced == {"objectHashSha1": "", "objectHashSha256": SHA256}
    assert real_sha1 == {"objectHashSha1": SHA1, "objectHashSha256": ""}


def test_sha1_field_not_overwriting_existing_sha256() -> None:
    both = {"objectHashSha1": SHA256, "objectHashSha256": "c" * 64}
    enrich(both)
    assert both["objectHashSha256"] == "c" * 64 and both["objectHashSha1"] == SHA256


def test_duration_gets_human_readable_sibling() -> None:
    incident = {"triageDuration": "339664.817892s", "resolveDuration": "90s", "name": "120s"}
    enrich(incident)
    assert incident["triageDurationHuman"] == "3d 22h 21m"
    assert incident["resolveDurationHuman"] == "1m 30s"
    assert "nameHuman" not in incident  # only *duration* fields


def test_description_literal_newlines_unescaped() -> None:
    incident = {"description": "Many failed logons.\\n\\nCheck the source."}
    enrich(incident)
    assert incident["description"] == "Many failed logons.\n\nCheck the source."


def test_description_with_windows_path_untouched() -> None:
    text = "Blocked C:\\Users\\nick\\app.exe"
    incident = {"description": text}
    enrich(incident)
    assert incident["description"] == text


def test_description_with_real_newlines_untouched() -> None:
    text = "Line one\nsee \\n literally"
    incident = {"description": text}
    enrich(incident)
    assert incident["description"] == text
