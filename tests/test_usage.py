"""Unit tests for the tool-usage log and its summary (no network)."""
from __future__ import annotations

import json

from eset_mcp.observability.usage import record_usage, summarize


def test_record_usage_appends_one_line_per_call(tmp_path) -> None:
    path = tmp_path / "nested" / "usage.jsonl"
    record_usage(str(path), tool="a", ok=True, status="ok", duration_ms=10)
    record_usage(str(path), tool="a", ok=False, status="404", duration_ms=30)
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert set(first) == {"ts", "tool", "ok", "status", "duration_ms"}


def test_record_usage_never_raises(tmp_path) -> None:
    # A directory where the file should be - writing fails, but must not raise.
    bad = tmp_path / "is-a-dir"
    bad.mkdir()
    record_usage(str(bad), tool="a", ok=True, status="ok", duration_ms=1)


def test_summarize_counts_per_tool_sorted_by_calls() -> None:
    lines = [
        json.dumps({"ts": "2026-10-26T10:00:00+00:00", "tool": "b", "ok": True, "status": "ok", "duration_ms": 100}),
        json.dumps({"ts": "2026-10-26T11:00:00+00:00", "tool": "a", "ok": True, "status": "ok", "duration_ms": 10}),
        json.dumps({"ts": "2026-10-26T12:00:00+00:00", "tool": "a", "ok": False, "status": "404", "duration_ms": 30}),
        json.dumps({"ts": "2026-10-26T13:00:00+00:00", "tool": "a", "ok": False, "status": "404", "duration_ms": 20}),
        "not json",
    ]
    rows = summarize(lines)
    assert [r["tool"] for r in rows] == ["a", "b"]
    a = rows[0]
    assert (a["calls"], a["ok"], a["failed"], a["avg_ms"]) == (3, 1, 2, 20)
    assert a["last"] == "2026-10-26T13:00:00+00:00"
    assert a["failures"] == {"404": 2}
