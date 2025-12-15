"""Submit an email file to the Sublime Analysis API and print the response."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional


def _ensure_backend_on_path() -> None:
    """Insert the backend package into sys.path when run from the repo root."""
    script_path = Path(__file__).resolve()
    project_root = script_path.parents[2]
    backend_dir = project_root / "backend"
    if str(backend_dir) not in sys.path:
        sys.path.insert(0, str(backend_dir))


_ensure_backend_on_path()

from app.services.providers.sublime import SublimeAnalysisClient  # noqa: E402  pylint: disable=wrong-import-position


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Submit an email artifact to Sublime and print the MDM payload.",
    )
    parser.add_argument("path", help="Path to an .eml, .msg, .json, or .mdm file.")
    parser.add_argument("--mailbox", help="Optional mailbox email address attribution.")
    parser.add_argument("--message-type", help="Optional Sublime message type hint.")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print the JSON response.")
    parser.add_argument(
        "--raw",
        action="store_true",
        help="Print the raw Sublime response without validating it against the MDM schema.",
    )
    parser.add_argument(
        "--analyze",
        action="store_true",
        help="Analyze the message against rules/queries instead of creating an MDM.",
    )
    parser.add_argument(
        "--rules-path",
        action="append",
        dest="rules_paths",
        help="Path to a rules/queries directory or YAML file. Can be supplied multiple times.",
    )
    parser.add_argument(
        "--run-all-detection-rules",
        action="store_true",
        help="Ask Sublime to run all detection rules against the message.",
    )
    parser.add_argument(
        "--run-active-detection-rules",
        action="store_true",
        help="Ask Sublime to run active detection rules against the message.",
    )
    parser.add_argument(
        "--run-all-insights",
        action="store_true",
        help="Ask Sublime to run all insight queries against the message.",
    )
    return parser.parse_args(argv)


def _load_rules_and_queries(paths: list[str]) -> tuple[list[dict], list[dict]]:
    """Load rule/query documents from the provided paths."""
    if not paths:
        return [], []

    from sublime import util as sublime_util  # imported lazily to avoid cost when unused

    all_rules: list[dict] = []
    all_queries: list[dict] = []
    for raw_path in paths:
        target = Path(raw_path).expanduser()
        if not target.exists():
            raise FileNotFoundError(target)

        if target.is_dir():
            rules, queries = sublime_util.load_yml_path(str(target))
        else:
            with target.open("r", encoding="utf-8") as stream:
                rules, queries = sublime_util.load_yml(stream)

        if rules:
            all_rules.extend(rules)
        if queries:
            all_queries.extend(queries)

    return all_rules, all_queries


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)

    submission_path = Path(args.path).expanduser()
    if not submission_path.exists():
        print(f"error: file not found: {submission_path}", file=sys.stderr)
        return 1

    client = SublimeAnalysisClient()

    if args.analyze:
        try:
            rules, queries = _load_rules_and_queries(args.rules_paths or [])
        except FileNotFoundError as exc:
            print(f"error: could not load rules: {exc}", file=sys.stderr)
            return 1
        except Exception as exc:  # pragma: no cover - interactive helper
            print(f"error: failed to load rules: {exc}", file=sys.stderr)
            return 1

        if not rules and not queries and not (
            args.run_all_detection_rules or args.run_active_detection_rules or args.run_all_insights
        ):
            print(
                "error: provide --rules-path or enable one of the --run-all-* flags when using --analyze.",
                file=sys.stderr,
            )
            return 1

        try:
            payload = client.analyze_message_from_path(
                submission_path,
                rules=rules or None,
                queries=queries or None,
                mailbox_email_address=args.mailbox,
                message_type=args.message_type,
                run_all_detection_rules=args.run_all_detection_rules,
                run_active_detection_rules=args.run_active_detection_rules,
                run_all_insights=args.run_all_insights,
            )
        except RuntimeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1

        print(json.dumps(payload, indent=2 if args.pretty else None))
        return 0

    if args.raw:
        from app.services import sublime_client as sublime_module  # noqa: E402

        loader = sublime_module._select_loader(submission_path)  # type: ignore[attr-defined]
        raw_message = loader(str(submission_path))
        payload = client.create_message_raw(
            raw_message,
            mailbox_email_address=args.mailbox,
            message_type=args.message_type,
        )
        print(json.dumps(payload, indent=2 if args.pretty else None))
        return 0

    try:
        mdm = client.create_message_from_path(
            submission_path,
            mailbox_email_address=args.mailbox,
            message_type=args.message_type,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        print("Tip: re-run with --raw to inspect the original Sublime payload.", file=sys.stderr)
        return 1

    payload = mdm.model_dump()
    print(json.dumps(payload, indent=2 if args.pretty else None))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
