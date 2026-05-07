from __future__ import annotations

import argparse
import json
from pathlib import Path

from .analyzer import GuardGraphAnalyzer
from .parser import FastAPIEndpointExtractor


def analyze_path(path: str | Path) -> dict:
    extractor = FastAPIEndpointExtractor(path).parse()
    return GuardGraphAnalyzer(extractor).analyze()


def main() -> None:
    parser = argparse.ArgumentParser(description="GuardGraph structural AppSec risk detector")
    parser.add_argument("target", help="Path to a FastAPI project")
    parser.add_argument("--output", "-o", help="Write JSON report to this path")
    args = parser.parse_args()

    report = analyze_path(args.target)
    report_json = json.dumps(report, indent=2, ensure_ascii=False)
    if args.output:
        Path(args.output).write_text(report_json, encoding="utf-8")
    else:
        print(report_json)


if __name__ == "__main__":
    main()
