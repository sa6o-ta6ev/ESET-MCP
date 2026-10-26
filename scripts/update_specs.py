"""Refresh the bundled ESET Connect OpenAPI specs from ESET's public Swagger.

ESET publishes the specs at https://eu.esetconnect.eset.systems/swagger/api/
and changes them without notice (new endpoints, renamed operationIds). The
tools are generated from these files, so refreshing them is how the server
picks up new read endpoints.

Usage:
    python scripts/update_specs.py          # download, then print what changed
    python scripts/update_specs.py --check  # exit 1 if anything changed, write nothing

After a refresh run the test suite: test_catalog_vs_openapi.py and
test_server_offline.py catch renamed tools that prompts or tests rely on.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import httpx

SWAGGER_URL = "https://eu.esetconnect.eset.systems/swagger/api/{name}.json"
OPENAPI_DIR = Path(__file__).resolve().parent.parent / "eset_mcp" / "openapi"
NON_SPEC_FILES = {"onprem-path-overrides.json"}


def _operations(spec: dict) -> dict[tuple[str, str], list[str]]:
    ops = {}
    for path, methods in spec.get("paths", {}).items():
        for method, op in methods.items():
            if method in {"get", "post", "put", "patch", "delete"}:
                ops[(method.upper(), path)] = sorted(
                    f"{p.get('in')}:{p.get('name')}" for p in op.get("parameters", []) if "name" in p
                )
    return ops


def _diff(name: str, old: dict, new: dict) -> list[str]:
    o, n = _operations(old), _operations(new)
    lines = [f"  + {m} {p}" for m, p in sorted(set(n) - set(o))]
    lines += [f"  - {m} {p}" for m, p in sorted(set(o) - set(n))]
    lines += [
        f"  ~ {m} {p} params +{sorted(set(n[(m, p)]) - set(o[(m, p)]))} -{sorted(set(o[(m, p)]) - set(n[(m, p)]))}"
        for m, p in sorted(set(o) & set(n))
        if o[(m, p)] != n[(m, p)]
    ]
    if not lines and old != new:
        lines.append("  (schemas/descriptions changed, operations unchanged)")
    return [f"{name}:", *lines] if lines else []


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--check", action="store_true", help="report drift without writing files")
    args = parser.parse_args()

    changed = False
    with httpx.Client(timeout=30) as client:
        for path in sorted(OPENAPI_DIR.glob("*.json")):
            if path.name in NON_SPEC_FILES:
                continue
            resp = client.get(SWAGGER_URL.format(name=path.stem), headers={"Accept": "application/json"})
            resp.raise_for_status()
            new = resp.json()
            if not str(new.get("openapi", "")).startswith("3") or "paths" not in new:
                print(f"{path.stem}: unexpected payload, skipped", file=sys.stderr)
                continue
            old = json.loads(path.read_text(encoding="utf-8"))
            report = _diff(path.stem, old, new)
            if report:
                changed = True
                print("\n".join(report))
                if not args.check:
                    path.write_text(json.dumps(new, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    if not changed:
        print("All specs are up to date.")
    return 1 if (changed and args.check) else 0


if __name__ == "__main__":
    sys.exit(main())
