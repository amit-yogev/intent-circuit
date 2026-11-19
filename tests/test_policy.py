import json
from pathlib import Path

from intent_circuit.engine import AgentAction, evaluate_sequence
from intent_circuit.policy import load_policy


def test_custom_policy_changes_decision(
    tmp_path: Path,
) -> None:
    policy_path = tmp_path / "custom_policy.json"

    policy_data = {
        "scores": {
            "read_sensitive": 30,
            "send_external": 20,
            "delete_file": 80,
            "sensitive_data_exfiltration": 100,
        },
        "thresholds": {
            "warn": 25,
            "approval": 50,
            "block": 75,
        },
    }

    policy_path.write_text(
        json.dumps(policy_data),
        encoding="utf-8",
    )

    custom_policy = load_policy(policy_path)

    actions = [
        AgentAction(
            name="delete_file",
            resource="production_database.db",
        ),
    ]

    decision, risk_score, _ = evaluate_sequence(
        actions,
        custom_policy,
    )

    assert risk_score == 80
    assert decision == "BLOCK"