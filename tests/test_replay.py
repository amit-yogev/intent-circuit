import json
from pathlib import Path

import pytest

from intent_circuit.engine import BUILTIN_POLICY_PATH
from intent_circuit.errors import IntentCircuitError
from intent_circuit.hook import STATE_DIR_ENV_VAR, handle_call
from intent_circuit.policy import load_policy
from intent_circuit.replay import (
    group_by_session,
    read_audit_log,
    redecide,
    session_summary,
)

POLICY = load_policy(BUILTIN_POLICY_PATH)


@pytest.fixture
def audit_log(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv(STATE_DIR_ENV_VAR, str(tmp_path))
    calls = [
        ("Read", {"file_path": "/app/README.md"}),
        ("Write", {"file_path": "/app/.vscode/tasks.json"}),
        ("Bash", {"command": "echo x > .git/hooks/pre-commit && git commit -m x"}),
    ]

    for tool_name, tool_input in calls:
        handle_call(
            {"session_id": "demo", "tool_name": tool_name, "tool_input": tool_input},
            POLICY,
        )

    return tmp_path / "audit.jsonl"


def test_log_is_read_in_order(audit_log: Path) -> None:
    entries = read_audit_log(audit_log)

    assert [entry["decision"] for entry in entries] == ["ALLOW", "APPROVAL", "BLOCK"]


def test_summary_counts_blocked_and_asked(audit_log: Path) -> None:
    sessions = group_by_session(read_audit_log(audit_log))

    assert session_summary("demo", sessions["demo"]) == (
        "Session demo: 3 decisions, 1 blocked, 1 asked"
    )


def test_same_policy_gives_the_same_decisions(audit_log: Path) -> None:
    entries = read_audit_log(audit_log)

    assert redecide(entries, POLICY) == ["ALLOW", "APPROVAL", "BLOCK"]


def test_stricter_policy_shows_what_would_change(
    audit_log: Path, tmp_path: Path
) -> None:
    data = json.loads(BUILTIN_POLICY_PATH.read_text(encoding="utf-8"))
    data["scores"]["write_trigger_file"] = 80
    strict_path = tmp_path / "strict.json"
    strict_path.write_text(json.dumps(data), encoding="utf-8")

    decisions = redecide(read_audit_log(audit_log), load_policy(strict_path))

    assert decisions == ["ALLOW", "BLOCK", "BLOCK"]


def test_old_entries_without_actions_are_not_decided_again(tmp_path: Path) -> None:
    log = tmp_path / "old.jsonl"
    log.write_text('{"session_id": "s", "decision": "BLOCK"}\n', encoding="utf-8")

    assert redecide(read_audit_log(log), POLICY) == [None]


def test_missing_log_is_a_clear_error(tmp_path: Path) -> None:
    with pytest.raises(IntentCircuitError, match="Audit log not found"):
        read_audit_log(tmp_path / "missing.jsonl")


@pytest.mark.parametrize("line", ["not json", '{"decision": "BLOCK"}'])
def test_broken_lines_name_the_line_number(tmp_path: Path, line: str) -> None:
    log = tmp_path / "audit.jsonl"
    log.write_text(
        '{"session_id": "s", "decision": "ALLOW"}\n' + line + "\n", encoding="utf-8"
    )

    with pytest.raises(IntentCircuitError, match="line 2"):
        read_audit_log(log)