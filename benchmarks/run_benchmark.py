#!/usr/bin/env python3
"""GuardGraph benchmark runner skeleton.

This file intentionally starts as a reproducibility scaffold. It does not yet
fetch third-party repositories or claim detections. Each case must be reviewed
and pinned to an exact vulnerable snapshot before being marked as reproduced.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parent
CASES_PATH = ROOT / "cases.yml"
RESULTS_DIR = ROOT / "results"


def load_cases() -> list[dict[str, Any]]:
    data = yaml.safe_load(CASES_PATH.read_text(encoding="utf-8")) or {}
    return data.get("cases", [])


def find_case(case_id: str) -> dict[str, Any]:
    for case in load_cases():
        if case.get("id") == case_id:
            return case
    raise SystemExit(f"Unknown benchmark case: {case_id}")


def print_case(case: dict[str, Any]) -> None:
    print(json.dumps(case, indent=2, ensure_ascii=False))


def main() -> None:
    parser = argparse.ArgumentParser(description="GuardGraph public vulnerability benchmark runner")
    parser.add_argument("--case", help="Case ID to inspect/run, e.g. CVE-2026-4505")
    parser.add_argument("--list", action="store_true", help="List benchmark cases")
    args = parser.parse_args()

    if args.list:
        for case in load_cases():
            print(f"{case.get('id')}\t{case.get('status')}\t{case.get('project', {}).get('name')}")
        return

    if not args.case:
        raise SystemExit("Use --list or --case CASE_ID")

    case = find_case(args.case)
    print_case(case)
    print("\nStatus: scaffold only. Pin vulnerable_ref and scan_target before claiming reproduction.")


if __name__ == "__main__":
    main()
