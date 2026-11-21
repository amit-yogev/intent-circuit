import json
from pathlib import Path
from typing import Any

import pytest

from intent_circuit.engine import KNOWN_ACTIONS, AgentAction
from intent_circuit.errors import InvalidScenarioError
from intent_circuit.runner import load_scenario


def write_scenario(tmp_path: Path, actions: list[Any]) -> Path:
    path = tmp_path / "scenario.json"
    path.write_text(
        json.dumps({"scenario_name": "Test", "actions": actions}),
        encoding="utf-8",
    )
    return path


def test_new_actions_are_known() -> None:
    assert {"write_file", "run_command", "network_request"} <= KNOWN_ACTIONS


def test_run_command_keeps_its_arguments(tmp_path: Path) -> None:
    scenario_path = write_scenario(
        tmp_path,
        [
            {
                "name": "run_command",
                "resource": "git",
                "args": ["-c", "core.fsmonitor=./payload.sh", "status"],
            }
        ],
    )

    _, actions = load_scenario(scenario_path)

    assert actions == [
        AgentAction(
            name="run_command",
            resource="git",
            args=("-c", "core.fsmonitor=./payload.sh", "status"),
        )
    ]


def test_escape_example_loads_every_step_in_order() -> None:
    scenario_name, actions = load_scenario(Path("examples/escape_attempt.json"))

    assert scenario_name == "Indirect sandbox escape through an editor task"
    assert [action.name for action in actions] == [
        "run_command",
        "write_file",
        "run_command",
        "network_request",
    ]


@pytest.mark.parametrize("bad_args", ["status", ["-c", 5], [None]])
def test_args_must_be_a_list_of_text(tmp_path: Path, bad_args: Any) -> None:
    scenario_path = write_scenario(
        tmp_path,
        [{"name": "run_command", "resource": "git", "args": bad_args}],
    )

    with pytest.raises(InvalidScenarioError, match="must be a list of text"):
        load_scenario(scenario_path)