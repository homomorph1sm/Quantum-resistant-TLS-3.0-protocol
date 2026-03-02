#!/usr/bin/env python3
"""Unified selftest entrypoint.

Covers:
- certificate lifecycle (CA + leaf issuance + verify)
- TLS 1.3 mutual-auth roundtrip using local server/client examples
- integrated PQ KEM and signature algorithms via autodiscovered backends
"""

from __future__ import annotations

import json
from pathlib import Path

from qr_tls.tools import UnifiedSelfTestRunner


def main() -> int:
    repo_root = Path(__file__).resolve().parent
    runner = UnifiedSelfTestRunner(repo_root)
    results = runner.run()

    print("== Unified SelfTest Report ==")
    failed = 0
    for item in results:
        icon = {"PASS": "✅", "FAIL": "❌", "SKIP": "⚠️"}.get(item.status, "•")
        print(f"{icon} {item.name}: {item.status} - {item.detail}")
        if item.status == "FAIL":
            failed += 1

    print("\nJSON_RESULT=")
    print(json.dumps(runner.as_jsonable(results), indent=2, ensure_ascii=False))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
