from __future__ import annotations

import argparse
import json
from pathlib import Path

from .analyzer import GuardGraphAnalyzer
from .markdown_report import render_markdown_report
from .parser import FastAPIEndpointExtractor


def analyze_path(path: str | Path) -> dict:
    extractor = FastAPIEndpointExtractor(path).parse()
    return GuardGraphAnalyzer(extractor).analyze()


def main() -> None:
    parser = argparse.ArgumentParser(description="GuardGraph structural AppSec risk detector")
    parser.add_argument("target", help="Path to a FastAPI project")
    parser.add_argument("--output", "-o", help="Write JSON report to this path")
    parser.add_argument("--markdown", "-m", help="Write human-readable Markdown report to this path")
    args = parser.parse_args()

    report = analyze_path(args.target)

    if args.output:
        Path(args.output).write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    elif not args.markdown:
        print(json.dumps(report, indent=2, ensure_ascii=False))

    if args.markdown:
        Path(args.markdown).write_text(render_markdown_report(report), encoding="utf-8")


if __name__ == "__main__":
    main()
