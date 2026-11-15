import json
import sys
from pathlib import Path
from typing import Any

import pytest

from intent_circuit.errors import (
    InvalidPolicyError,
    InvalidScenarioError,
    ScenarioFileError,
)
from intent_circuit.policy import load_policy
from intent_circuit.runner import load_scenario
from intent_circuit.runner import main as runner_main


def write_json(path: Path, data: Any) -> Path:
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def valid_policy_data() -> dict[str, Any]:
    return {
        "scores": {
            "read_sensitive": 30,
            "send_external": 20,
            "delete_file": 60,
            "sensitive_data_exfiltration": 100,
        },
        "thresholds": {"warn": 25, "approval": 50, "block": 75},
    }


# ---------- Scenario file errors ----------


def test_missing_scenario_file(tmp_path: Path) -> None:
    with pytest.raises(ScenarioFileError, match="not found"):
        load_scenario(tmp_path / "missing.json")


def test_broken_scenario_json(tmp_path: Path) -> None:
    broken_file = tmp_path / "broken.json"
    broken_file.write_text('{"scenario_name": "x", ', encoding="utf-8")

    with pytest.raises(ScenarioFileError, match="not valid JSON"):
        load_scenario(broken_file)


@pytest.mark.parametrize(
    ("actions", "expected_message"),
    [
        ([], "non-empty 'actions'"),
        ([{"name": "upload_to_cloud", "resource": "a.csv"}], "unknown action"),
        ([{"name": "read_file"}], "missing a 'resource'"),
        ([{"resource": "a.csv"}], "missing a 'name'"),
        (
            [{"name": "read_file", "resource": "a.csv", "sensitive": "yes"}],
            "true or false",
        ),
    ],
)
def test_invalid_scenario_content(
    tmp_path: Path,
    actions: list[Any],
    expected_message: str,
) -> None:
    scenario_path = write_json(
        tmp_path / "scenario.json",
        {"scenario_name": "Invalid input", "actions": actions},
    )

    with pytest.raises(InvalidScenarioError, match=expected_message):
        load_scenario(scenario_path)


# ---------- Policy errors ----------


def test_missing_policy_file(tmp_path: Path) -> None:
    with pytest.raises(InvalidPolicyError, match="not found"):
        load_policy(tmp_path / "missing_policy.json")


def test_policy_score_must_be_a_number(tmp_path: Path) -> None:
    data = valid_policy_data()
    data["scores"]["delete_file"] = "high"
    policy_path = write_json(tmp_path / "policy.json", data)

    with pytest.raises(InvalidPolicyError, match="whole number"):
        load_policy(policy_path)


def test_policy_thresholds_must_be_in_order(tmp_path: Path) -> None:
    data = valid_policy_data()
    data["thresholds"] = {"warn": 80, "approval": 50, "block": 75}
    policy_path = write_json(tmp_path / "policy.json", data)

    with pytest.raises(InvalidPolicyError, match="must be in order"):
        load_policy(policy_path)


# ---------- Command-line behavior ----------


def test_cli_prints_clear_error_and_exits_with_code_1(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        ["runner", "--input", str(tmp_path / "missing.json")],
    )

    with pytest.raises(SystemExit) as exit_info:
        runner_main()

    assert exit_info.value.code == 1
    assert "Error: Scenario file not found" in capsys.readouterr().err