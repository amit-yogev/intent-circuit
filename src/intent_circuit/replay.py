import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .engine import AgentAction
from .errors import IntentCircuitError
from .hook import decide, state_dir
from .policy import SecurityPolicy, load_policy

REQUIRED_FIELDS = frozenset({"session_id", "decision"})


def default_log_path() -> Path:
    return state_dir() / "audit.jsonl"


def read_audit_log(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise IntentCircuitError(f"Audit log not found: {path}")

    entries = []

    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue

        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            raise IntentCircuitError(
                f"Audit log line {number} is not valid JSON."
            ) from None

        if not isinstance(entry, dict) or not REQUIRED_FIELDS <= entry.keys():
            raise IntentCircuitError(f"Audit log line {number} is not a decision.")

        entries.append(entry)

    return entries


def group_by_session(entries: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    sessions: dict[str, list[dict[str, Any]]] = {}

    for entry in entries:
        sessions.setdefault(entry["session_id"], []).append(entry)

    return sessions


def redecide(
    entries: list[dict[str, Any]], policy: SecurityPolicy
) -> list[str | None]:
    history: list[AgentAction] = []
    decisions: list[str | None] = []

    for entry in entries:
        if "actions" not in entry:
            decisions.append(None)
            continue

        actions = [
            AgentAction(**{**item, "args": tuple(item["args"])})
            for item in entry["actions"]
        ]
        decision, _, _ = decide(history, actions, policy)
        decisions.append(decision)

        if decision != "BLOCK":
            history.extend(actions)

    return decisions


def format_entry(entry: dict[str, Any]) -> str:
    time = str(entry.get("time", ""))[11:19]
    return (
        f"  {time}  {entry.get('tool_name', ''):<10} {entry['decision']:<9}"
        f" {entry.get('risk_score', 0):>3}  {entry.get('reason', '')}"
    )


def session_summary(session_id: str, entries: list[dict[str, Any]]) -> str:
    decisions = [entry["decision"] for entry in entries]
    return (
        f"Session {session_id}: {len(entries)} decisions, "
        f"{decisions.count('BLOCK')} blocked, {decisions.count('APPROVAL')} asked"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Replay IntentCircuit decisions.")
    parser.add_argument("--log", default=default_log_path(), type=Path)
    parser.add_argument("--session", help="Show only this session")
    parser.add_argument("--policy", type=Path, help="Decide again with this policy")
    args = parser.parse_args()

    try:
        sessions = group_by_session(read_audit_log(args.log))
        policy = load_policy(args.policy) if args.policy else None
    except IntentCircuitError as error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(1)

    for session_id, entries in sessions.items():
        if args.session and session_id != args.session:
            continue

        print(session_summary(session_id, entries))
        new_decisions = redecide(entries, policy) if policy else [None] * len(entries)

        for entry, new_decision in zip(entries, new_decisions):
            print(format_entry(entry))

            if new_decision is not None and new_decision != entry["decision"]:
                print(f"            -> with this policy: {new_decision}")

        print()


if __name__ == "__main__":
    main()