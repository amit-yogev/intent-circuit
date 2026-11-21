import json
from pathlib import Path

import pytest

from intent_circuit.engine import (
    BUILTIN_POLICY_PATH,
    AgentAction,
    evaluate_sequence,
)
from intent_circuit.errors import InvalidPolicyError
from intent_circuit.policy import load_policy
from intent_circuit.runner import load_scenario

WRITE_HOOK = AgentAction(name="write_file", resource=".git/hooks/pre-commit")
GIT_COMMIT = AgentAction(
    name="run_command", resource="git", args=("commit", "-m", "Update docs")
)


def evaluate(actions: list[AgentAction]) -> tuple[str, int, str]:
    return evaluate_sequence(actions, load_policy(BUILTIN_POLICY_PATH))


def test_writing_a_hook_then_running_git_is_blocked() -> None:
    decision, risk_score, reason = evaluate([WRITE_HOOK, GIT_COMMIT])

    assert decision == "BLOCK"
    assert risk_score == 100
    assert "a trap was set and then triggered" in reason


def test_running_git_alone_is_allowed() -> None:
    decision, risk_score, _ = evaluate([GIT_COMMIT])

    assert decision == "ALLOW"
    assert risk_score == 0


def test_order_matters() -> None:
    decision, risk_score, reason = evaluate([GIT_COMMIT, WRITE_HOOK])

    assert decision == "APPROVAL"
    assert risk_score == 60
    assert "trap" not in reason


def test_ordinary_file_then_git_is_allowed() -> None:
    write_code = AgentAction(name="write_file", resource="src/app.py")

    decision, risk_score, _ = evaluate([write_code, GIT_COMMIT])

    assert decision == "ALLOW"
    assert risk_score == 0


@pytest.mark.parametrize(
    "program",
    ["/usr/bin/git", "C:\\Program Files\\Git\\cmd\\git.exe", "GIT"],
)
def test_program_path_and_case_do_not_hide_git(program: str) -> None:
    run_git = AgentAction(name="run_command", resource=program, args=("status",))

    decision, _, _ = evaluate([WRITE_HOOK, run_git])

    assert decision == "BLOCK"


def test_ci_workflow_then_push_is_blocked() -> None:
    write_workflow = AgentAction(
        name="write_file", resource=".github/workflows/deploy.yml"
    )
    git_push = AgentAction(name="run_command", resource="git", args=("push",))

    decision, _, _ = evaluate([write_workflow, git_push])

    assert decision == "BLOCK"


def test_a_trap_is_reported_once() -> None:
    git_push = AgentAction(name="run_command", resource="git", args=("push",))

    _, _, reason = evaluate([WRITE_HOOK, GIT_COMMIT, git_push])

    assert reason.count("a trap was set") == 1


def test_hook_trap_example_is_blocked() -> None:
    _, actions = load_scenario(Path("examples/hook_trap.json"))

    decision, _, _ = evaluate(actions)

    assert decision == "BLOCK"


def test_activated_by_must_be_a_list_of_programs(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(
        json.dumps(
            {
                "scores": {
                    "read_sensitive": 30,
                    "send_external": 20,
                    "delete_file": 60,
                    "sensitive_data_exfiltration": 100,
                },
                "thresholds": {"warn": 25, "approval": 50, "block": 75},
                "trigger_files": [
                    {
                        "pattern": ".git/hooks/*",
                        "reason": "Git runs hooks automatically",
                        "activated_by": "git",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(InvalidPolicyError, match="'activated_by' must be a list"):
        load_policy(policy_path)