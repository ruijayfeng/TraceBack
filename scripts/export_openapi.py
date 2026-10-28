#!/usr/bin/env python3
"""F21: export the workbench OpenAPI schema snapshot used by contract tests.

Usage (from the repository root):
    PYTHONPATH=backend python scripts/export_openapi.py
    PYTHONPATH=backend python scripts/export_openapi.py --check
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.api.workbench import create_workbench_app  # noqa: E402

SNAPSHOT = ROOT / "docs" / "openapi-workbench.json"
HTTP_METHODS = {"get", "put", "post", "delete", "patch", "options", "head"}


def operations(schema: dict) -> dict[str, list[str]]:
    return {
        path: sorted(method for method in methods if method in HTTP_METHODS)
        for path, methods in schema.get("paths", {}).items()
    }


def build() -> dict:
    app = create_workbench_app(ROOT)
    return app.openapi()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail if the committed snapshot drifts")
    args = parser.parse_args()
    schema = build()
    operations_now = operations(schema)
    if args.check:
        if not SNAPSHOT.is_file():
            print(f"missing snapshot: {SNAPSHOT}", file=sys.stderr)
            return 1
        expected = operations(json.loads(SNAPSHOT.read_text(encoding="utf-8")))
        if expected != operations_now:
            print("OpenAPI workbench route snapshot drifted.", file=sys.stderr)
            for path in sorted(set(expected) | set(operations_now)):
                if expected.get(path) != operations_now.get(path):
                    print(f"  {path}: {expected.get(path)} -> {operations_now.get(path)}", file=sys.stderr)
            return 1
        print(f"OpenAPI workbench snapshot matches ({len(operations_now)} paths).")
        return 0
    SNAPSHOT.parent.mkdir(parents=True, exist_ok=True)
    SNAPSHOT.write_text(json.dumps(schema, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote {SNAPSHOT} ({len(operations_now)} paths).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
