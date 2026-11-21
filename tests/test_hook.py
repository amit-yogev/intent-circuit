import pytest

from intent_circuit.engine import AgentAction
from intent_circuit.hook import actions_from_tool_call, split_commands


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("git status", [["git", "status"]]),
        ("cd src && git commit -m x", [["cd", "src"], ["git", "commit", "-m", "x"]]),
        ("ls | grep x; pytest -v", [["ls"], ["grep", "x"], ["pytest", "-v"]]),
        ('git commit -m "fix: a && b"', [["git", "commit", "-m", "fix: a && b"]]),
    ],
)
def test_commands_are_split_like_a_shell(command: str, expected: list) -> None:
    assert split_commands(command) == expected


def test_unclosed_quote_does_not_crash() -> None:
    assert split_commands("echo 'unclosed") == [["echo", "'unclosed"]]


def test_bash_call_becomes_one_action_per_command() -> None:
    actions = actions_from_tool_call(
        "Bash", {"command": "cd app && git -c core.fsmonitor=./x.sh status"}
    )

    assert actions == [
        AgentAction(name="run_command", resource="cd", args=("app",)),
        AgentAction(
            name="run_command",
            resource="git",
            args=("-c", "core.fsmonitor=./x.sh", "status"),
        ),
    ]


@pytest.mark.parametrize("tool_name", ["Write", "Edit", "MultiEdit"])
def test_file_tools_become_writes(tool_name: str) -> None:
    actions = actions_from_tool_call(
        tool_name, {"file_path": "C:\\project\\.vscode\\tasks.json"}
    )

    assert actions == [
        AgentAction(name="write_file", resource="C:\\project\\.vscode\\tasks.json")
    ]


def test_read_and_web_fetch_are_translated() -> None:
    assert actions_from_tool_call("Read", {"file_path": "/app/README.md"}) == [
        AgentAction(name="read_file", resource="/app/README.md")
    ]
    assert actions_from_tool_call("WebFetch", {"url": "http://169.254.169.254/"}) == [
        AgentAction(name="network_request", resource="http://169.254.169.254/")
    ]


def test_tools_that_change_nothing_are_not_judged() -> None:
    assert actions_from_tool_call("Grep", {"pattern": "TODO"}) == []