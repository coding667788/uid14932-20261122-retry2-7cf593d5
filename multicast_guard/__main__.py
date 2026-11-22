"""Command line entry point: ``python -m multicast_guard <plan|check> CASE.json``."""

from __future__ import annotations

import argparse
import json
import sys

from .errors import InputError, ValidationError
from .model import load_document, parse_case
from .serialize import build_plan_payload
from .verifier import verify


def _emit(payload: dict) -> None:
    sys.stdout.write(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=False) + "\n"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m multicast_guard",
        description="Offline dual multicast-tree planning and audit tool "
                    "(synthetic inputs, two simulated encapsulation labels).",
    )
    parser.add_argument("command", choices=("plan", "check"))
    parser.add_argument("case_file", help="path to the synthetic CASE.json document")
    args = parser.parse_args(argv)

    try:
        doc = load_document(args.case_file)
        case = parse_case(doc)
    except InputError as exc:
        _emit(exc.to_payload())
        return 2
    except ValidationError as exc:
        _emit(exc.to_payload())
        return 2

    if args.command == "plan":
        payload = build_plan_payload(case)
    else:
        payload = {"command": "check", **verify(case)}
    _emit(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
