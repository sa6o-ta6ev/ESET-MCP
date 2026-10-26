"""Tool-usage log: one JSON line per tool call, plus a summary command.

Works on every transport (unlike Prometheus, which needs HTTP), and survives
restarts, so it answers "which tools get used, and how often do they fail"
over days or weeks of local use.

Each record holds only: timestamp, tool name, ok flag, status, duration.
Never arguments, results, usernames or tenant data.

Summarise with::

    eset-mcp-stats [path]        # path defaults to $ESET_MCP_USAGE_LOG
"""
from __future__ import annotations

import datetime as _dt
import json
import logging
import os
import sys
from collections import defaultdict
from pathlib import Path

_LOG = logging.getLogger("eset_mcp.usage")


def record_usage(path: str, *, tool: str, ok: bool, status: str, duration_ms: int) -> None:
    """Append one usage record. Best-effort: failures are logged, never raised."""
    record = {
        "ts": _dt.datetime.now(_dt.UTC).isoformat(timespec="seconds"),
        "tool": tool,
        "ok": ok,
        "status": status,
        "duration_ms": duration_ms,
    }
    try:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
    except OSError:
        _LOG.exception("could not write usage record to %s", path)


def summarize(lines: list[str]) -> list[dict[str, object]]:
    """Aggregate usage records per tool, most-called first."""
    stats: dict[str, dict[str, object]] = defaultdict(
        lambda: {"calls": 0, "ok": 0, "failed": 0, "total_ms": 0, "last": "", "statuses": defaultdict(int)}
    )
    for line in lines:
        try:
            rec = json.loads(line)
            tool = rec["tool"]
        except (ValueError, KeyError, TypeError):
            continue
        s = stats[tool]
        s["calls"] += 1  # type: ignore[operator]
        s["ok" if rec.get("ok") else "failed"] += 1  # type: ignore[operator]
        s["total_ms"] += int(rec.get("duration_ms", 0))  # type: ignore[operator]
        s["last"] = max(str(s["last"]), str(rec.get("ts", "")))
        if not rec.get("ok"):
            s["statuses"][str(rec.get("status", "error"))] += 1  # type: ignore[index]
    rows = []
    for tool, s in stats.items():
        rows.append({
            "tool": tool,
            "calls": s["calls"],
            "ok": s["ok"],
            "failed": s["failed"],
            "avg_ms": int(s["total_ms"]) // int(s["calls"]),  # type: ignore[call-overload]
            "last": s["last"],
            "failures": dict(s["statuses"]),  # type: ignore[call-overload]
        })
    rows.sort(key=lambda r: (-int(r["calls"]), str(r["tool"])))  # type: ignore[call-overload]
    return rows


def main() -> None:
    """``eset-mcp-stats`` entry point: print a per-tool table."""
    path = sys.argv[1] if len(sys.argv) > 1 else os.getenv("ESET_MCP_USAGE_LOG", "")
    if not path:
        sys.exit("usage: eset-mcp-stats <usage-log.jsonl>  (or set ESET_MCP_USAGE_LOG)")
    p = Path(os.path.expanduser(path))
    if not p.exists():
        sys.exit(f"no usage log at {p}")
    rows = summarize(p.read_text(encoding="utf-8").splitlines())
    if not rows:
        print("no tool calls recorded yet")
        return
    width = max(len("tool"), *(len(str(r["tool"])) for r in rows))
    print(f"{'tool':<{width}}  {'calls':>6}  {'ok':>6}  {'failed':>6}  {'avg_ms':>7}  last call (UTC)       failures")
    for r in rows:
        failures = ", ".join(f"{k}x{v}" for k, v in r["failures"].items())  # type: ignore[attr-defined]
        print(
            f"{r['tool']!s:<{width}}  {r['calls']:>6}  {r['ok']:>6}  {r['failed']:>6}  "
            f"{r['avg_ms']:>7}  {r['last']!s:<20}  {failures}"
        )
    total = sum(int(r["calls"]) for r in rows)  # type: ignore[call-overload]
    failed = sum(int(r["failed"]) for r in rows)  # type: ignore[call-overload]
    print(f"\n{total} calls, {failed} failed, {len(rows)} distinct tools")
