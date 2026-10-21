"""Command-line diagnostics for the demo task pipeline.

The CLI only exposes bounded demo work; it never accepts callable names or
arbitrary task definitions. It shares the API adapter, so the queue backend is
whatever ``ITSM_*`` configuration selects.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from itsm.config import Settings, get_settings
from itsm.tasks import TaskQueue, TaskStorageUnavailable, create_task_queue


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="itsm-tasks",
        description="Bounded demo task diagnostics for the ITSM backend.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    demo = commands.add_parser("submit-demo", help="queue the bounded echo task")
    demo.add_argument("message")
    demo.add_argument("--delay", type=int, default=0, help="seconds to delay (0-300)")

    failure = commands.add_parser(
        "submit-demo-failure",
        help="queue a bounded failing task to verify retry handling",
    )
    failure.add_argument("message")

    status = commands.add_parser("status", help="read a stored task state")
    status.add_argument("task_id")
    return parser


def _emit(payload: dict[str, object], *, exit_code: int = 0) -> int:
    stream = sys.stdout if exit_code == 0 else sys.stderr
    stream.write(json.dumps(payload) + "\n")
    return exit_code


def _submit_demo(queue: TaskQueue, settings: Settings, message: str, delay: int) -> int:
    if not 1 <= len(message) <= settings.demo_message_max_length:
        return _emit(
            {"error": f"message must be 1-{settings.demo_message_max_length} characters"},
            exit_code=2,
        )
    if not 0 <= delay <= settings.demo_max_delay_seconds:
        return _emit(
            {"error": f"delay must be 0-{settings.demo_max_delay_seconds} seconds"},
            exit_code=2,
        )
    status = queue.submit_demo(message, delay_seconds=delay)
    return _emit({"task_id": status.task_id, "state": status.state.value})


def _submit_failure(queue: TaskQueue, settings: Settings, message: str) -> int:
    if not 1 <= len(message) <= settings.demo_message_max_length:
        return _emit(
            {"error": f"message must be 1-{settings.demo_message_max_length} characters"},
            exit_code=2,
        )
    status = queue.submit_demo_failure(message)
    return _emit({"task_id": status.task_id, "state": status.state.value})


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    settings = get_settings()
    queue = create_task_queue(settings)
    try:
        if args.command == "submit-demo":
            return _submit_demo(queue, settings, args.message, args.delay)
        if args.command == "submit-demo-failure":
            return _submit_failure(queue, settings, args.message)
        status = queue.get_status(args.task_id)
    except TaskStorageUnavailable as exc:
        return _emit({"error": str(exc)}, exit_code=1)

    if status is None:
        return _emit({"error": "task not found"}, exit_code=1)
    return _emit(
        {
            "task_id": status.task_id,
            "state": status.state.value,
            "result": status.result,
            "error": status.error,
            "retries_remaining": status.retries_remaining,
        }
    )


if __name__ == "__main__":  # pragma: no cover - module entrypoint
    raise SystemExit(main())
