from __future__ import annotations

import argparse
import json
from pathlib import Path

from .analyzer import GuardGraphAnalyzer
from .config import GuardGraphConfig, default_config, load_config
from .markdown_report import render_markdown_report
from .parser import FastAPIEndpointExtractor


def analyze_path(path: str | Path) -> dict:
    extractor = FastAPIEndpointExtractor(path).parse()
    return GuardGraphAnalyzer(extractor).analyze()


def run_with_config(config: GuardGraphConfig, *, target_override: str | None = None) -> dict:
    target_path = target_override or config.target.path
    report = analyze_path(target_path)
    _write_reports(report, json_path=config.report.json, markdown_path=config.report.markdown)
    return report


def _write_reports(report: dict, *, json_path: str | None, markdown_path: str | None) -> None:
    if json_path:
        Path(json_path).write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    if markdown_path:
        Path(markdown_path).write_text(render_markdown_report(report), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="GuardGraph structural AppSec risk detector")
    parser.add_argument("target", nargs="?", help="Path to a FastAPI project")
    parser.add_argument("--target", dest="target_override", help="Override target path from config")
    parser.add_argument("--config", "-c", help="Path to guardgraph.yml")
    parser.add_argument("--output", "-o", help="Write JSON report to this path")
    parser.add_argument("--markdown", "-m", help="Write human-readable Markdown report to this path")
    args = parser.parse_args()

    if args.config:
        cfg = load_config(args.config)
        target_path = args.target_override or args.target or cfg.target.path
        json_out = args.output if args.output is not None else cfg.report.json
        md_out = args.markdown if args.markdown is not None else cfg.report.markdown
    else:
        cfg = default_config()
        target_path = args.target_override or args.target or cfg.target.path
        json_out = args.output
        md_out = args.markdown

    report = analyze_path(target_path)

    if json_out or md_out:
        _write_reports(report, json_path=json_out, markdown_path=md_out)
    else:
        print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
