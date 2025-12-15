"""Filter Sublime analysis output down to matched rules and meaningful insights."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any


def _is_truthy_result(value: Any) -> bool:
    """Return True when a query result carries meaningful information."""
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, (list, tuple, dict, set)):
        return len(value) > 0
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip() != ""
    return True


def _filter_payload(payload: dict[str, Any], *, include_workflow_rules: bool) -> dict[str, Any]:
    def _is_detection_rule(item: dict[str, Any]) -> bool:
        if include_workflow_rules:
            return True
        rule = item.get("rule", {})
        # Workflow / playbook helpers typically have no severity or trivial sources like "true".
        has_severity = rule.get("severity") not in (None, "", "null")
        non_trivial_source = rule.get("source", "").strip().lower() not in {"true", ""}
        return has_severity or non_trivial_source

    rule_hits = [
        item
        for item in payload.get("rule_results", [])
        if item.get("matched") and _is_detection_rule(item)
    ]
    insight_hits = [
        item
        for item in payload.get("query_results", [])
        if _is_truthy_result(item.get("result"))
    ]
    return {"rule_hits": rule_hits, "insight_hits": insight_hits}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Print only matched rules and truthy insights from a Sublime analysis JSON file.",
    )
    parser.add_argument(
        "path",
        nargs="?",
        default="backend/analysis_output.json",
        help="Path to the analysis_output.json file (default). Use '-' to read from stdin.",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Optional path to write the filtered JSON. If omitted, prints to stdout.",
    )
    parser.add_argument(
        "--compact",
        action="store_true",
        help="Emit compact JSON without indentation.",
    )
    parser.add_argument(
        "--include-workflow-rules",
        action="store_true",
        help="Keep workflow/playbook rules (severity-less helpers) in the output.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    piped_payload: str | None = None

    if args.path == "-" or not sys.stdin.isatty():
        raw = sys.stdin.read()
        if raw.strip():
            piped_payload = raw

    if piped_payload is not None:
        try:
            payload = json.loads(piped_payload)
        except json.JSONDecodeError as exc:
            print(f"error: failed to parse piped JSON: {exc}")
            return 1
    else:
        input_path = Path(args.path)

        if not input_path.exists():
            print(f"error: analysis file not found: {input_path}")
            return 1

        try:
            payload = json.loads(input_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            print(f"error: failed to parse JSON from {input_path}: {exc}")
            return 1

    filtered = _filter_payload(payload, include_workflow_rules=args.include_workflow_rules)
    indent = None if args.compact else 2
    content = json.dumps(filtered, indent=indent)

    if args.output:
        Path(args.output).write_text(content + ("\n" if not args.compact else ""), encoding="utf-8")
    else:
        print(content)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
