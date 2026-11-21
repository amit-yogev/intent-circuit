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


def evaluate_write(path: str) -> tuple[str, int, str]:
    policy = load_policy(BUILTIN_POLICY_PATH)
    return evaluate_sequence([AgentAction(name="write_file", resource=path)], policy)


def test_writing_an_editor_task_needs_approval() -> None:
    decision, risk_score, reason = evaluate_write(".vscode/tasks.json")

    assert decision == "APPROVAL"
    assert risk_score == 60
    assert "execution-trigger file: .vscode/tasks.json" in reason


@pytest.mark.parametrize(
    "path",
    [
        "./.vscode/tasks.json",
        "project\\.vscode\\tasks.json",
        "/workspace/app/.git/hooks/pre-commit",
        ".GIT/config",
        ".github/workflows/deploy.yml",
        ".venv/Scripts/python.exe",
        ".venv/bin/python3",
        ".claude/settings.local.json",
    ],
)
def test_trigger_files_are_recognized(path: str) -> None:
    decision, risk_score, _ = evaluate_write(path)

    assert decision == "APPROVAL"
    assert risk_score == 60


@pytest.mark.parametrize(
    "path",
    [
        "src/app.py",
        "docs/vscode-tasks.md",
        ".venv/lib/site-packages/requests/__init__.py",
    ],
)
def test_ordinary_files_are_allowed(path: str) -> None:
    decision, risk_score, _ = evaluate_write(path)

    assert decision == "ALLOW"
    assert risk_score == 0


def test_escape_example_is_no_longer_allowed() -> None:
    _, actions = load_scenario(Path("examples/escape_attempt.json"))
    policy = load_policy(BUILTIN_POLICY_PATH)

    decision, _, _ = evaluate_sequence(actions, policy)

    assert decision in {"APPROVAL", "BLOCK"}


def test_trigger_file_needs_a_reason(tmp_path: Path) -> None:
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
                "trigger_files": [{"pattern": ".vscode/tasks.json"}],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(InvalidPolicyError, match="needs a 'reason'"):
        load_policy(policy_path)