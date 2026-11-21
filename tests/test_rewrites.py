import pytest

from intent_circuit.engine import (
    BUILTIN_POLICY_PATH,
    AgentAction,
    evaluate_sequence,
    unwrap_command,
)
from intent_circuit.policy import canonical_host, host_of, load_policy


def evaluate(actions: list[AgentAction]) -> tuple[str, int, str]:
    return evaluate_sequence(actions, load_policy(BUILTIN_POLICY_PATH))


def run(program: str, *args: str) -> AgentAction:
    return AgentAction(name="run_command", resource=program, args=args)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("http://2852039166/latest/meta-data/", "169.254.169.254"),
        ("http://[fd00:ec2:0:0:0:0:0:254]/", "fd00:ec2::254"),
        ("https://pypi.org/simple/", "pypi.org"),
    ],
)
def test_addresses_are_written_one_way(text: str, expected: str) -> None:
    assert host_of(text) == expected


def test_a_number_too_large_for_an_address_is_kept() -> None:
    assert canonical_host("99999999999") == "99999999999"


@pytest.mark.parametrize(
    "url",
    [
        "http://2852039166/latest/meta-data/",
        "http://[fd00:ec2::254]/latest/meta-data/",
    ],
)
def test_other_spellings_of_the_metadata_service_are_blocked(url: str) -> None:
    decision, _, _ = evaluate([AgentAction(name="network_request", resource=url)])

    assert decision == "BLOCK"


def test_env_reveals_the_program_it_starts() -> None:
    program, args = unwrap_command("env", ("A=1", "git", "status"))

    assert program == "git"
    assert args == ("A=1", "status")


def test_env_alone_stays_env() -> None:
    assert unwrap_command("env", ("A=1",)) == ("env", ("A=1",))


def test_git_setting_hidden_in_env_is_blocked() -> None:
    decision, _, reason = evaluate(
        [
            run(
                "env",
                "GIT_CONFIG_PARAMETERS='core.fsmonitor=./payload.sh'",
                "git",
                "status",
            )
        ]
    )

    assert decision == "BLOCK"
    assert "Ran git with" in reason


def test_trap_triggered_through_env_is_blocked() -> None:
    decision, risk_score, _ = evaluate(
        [
            AgentAction(name="write_file", resource=".git/hooks/pre-commit"),
            run("env", "GIT_AUTHOR_NAME=x", "git", "commit", "-m", "x"),
        ]
    )

    assert decision == "BLOCK"
    assert risk_score == 100


def test_ordinary_env_use_is_allowed() -> None:
    decision, risk_score, _ = evaluate([run("env", "PYTHONPATH=src", "pytest")])

    assert decision == "ALLOW"
    assert risk_score == 0


@pytest.mark.parametrize(
    ("mode", "expected"),
    [("4755", "BLOCK"), ("755", "ALLOW"), ("0755", "ALLOW")],
)
def test_numeric_setuid_is_blocked(mode: str, expected: str) -> None:
    decision, _, _ = evaluate([run("chmod", mode, "/bin/bash")])

    assert decision == expected