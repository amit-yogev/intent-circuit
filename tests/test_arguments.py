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


def evaluate(actions: list[AgentAction]) -> tuple[str, int, str]:
    return evaluate_sequence(actions, load_policy(BUILTIN_POLICY_PATH))


def run(program: str, *args: str) -> AgentAction:
    return AgentAction(name="run_command", resource=program, args=args)


def test_escape_example_is_blocked() -> None:
    _, actions = load_scenario(Path("examples/escape_attempt.json"))

    decision, risk_score, reason = evaluate(actions)

    assert decision == "BLOCK"
    assert risk_score == 100
    assert "core.fsmonitor=./payload.sh" in reason
    assert "169.254.169.254" in reason


def test_git_fsmonitor_argument_is_blocked() -> None:
    decision, risk_score, reason = evaluate(
        [run("git", "-c", "core.fsmonitor=./payload.sh", "status")]
    )

    assert decision == "BLOCK"
    assert risk_score == 80
    assert "Ran git with core.fsmonitor=./payload.sh" in reason


def test_git_config_hooks_path_is_blocked() -> None:
    decision, _, _ = evaluate([run("git", "config", "core.hooksPath", ".hooks")])

    assert decision == "BLOCK"


@pytest.mark.parametrize(
    "args",
    [
        ("status",),
        ("commit", "-m", "Fix typo"),
        ("-c", "user.name=Amit", "commit", "-m", "Fix typo"),
    ],
)
def test_ordinary_git_is_allowed(args: tuple[str, ...]) -> None:
    decision, risk_score, _ = evaluate([run("git", *args)])

    assert decision == "ALLOW"
    assert risk_score == 0


def test_docker_socket_is_blocked() -> None:
    decision, risk_score, _ = evaluate(
        [
            run(
                "curl",
                "--unix-socket",
                "/var/run/docker.sock",
                "http://localhost/containers/json",
            )
        ]
    )

    assert decision == "BLOCK"
    assert risk_score == 90


def test_privileged_container_is_blocked() -> None:
    decision, _, _ = evaluate([run("docker", "run", "--privileged", "ubuntu")])

    assert decision == "BLOCK"


def test_ordinary_container_is_allowed() -> None:
    decision, _, _ = evaluate([run("docker", "run", "python:3.13")])

    assert decision == "ALLOW"


def test_sudo_needs_approval() -> None:
    decision, risk_score, _ = evaluate([run("sudo", "apt", "install", "curl")])

    assert decision == "APPROVAL"
    assert risk_score == 50


def test_setuid_is_blocked_but_executable_bit_is_allowed() -> None:
    setuid_decision, _, _ = evaluate([run("chmod", "u+s", "/bin/bash")])
    executable_decision, _, _ = evaluate([run("chmod", "+x", "build.sh")])

    assert setuid_decision == "BLOCK"
    assert executable_decision == "ALLOW"


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data/",
        "http://METADATA.google.internal/computeMetadata/v1/",
    ],
)
def test_cloud_metadata_request_is_blocked(url: str) -> None:
    decision, risk_score, _ = evaluate(
        [AgentAction(name="network_request", resource=url)]
    )

    assert decision == "BLOCK"
    assert risk_score == 90


def test_ordinary_network_request_is_allowed() -> None:
    decision, _, _ = evaluate(
        [AgentAction(name="network_request", resource="https://pypi.org/simple/")]
    )

    assert decision == "ALLOW"


def test_curl_to_cloud_metadata_is_blocked() -> None:
    decision, _, reason = evaluate(
        [run("curl", "http://169.254.169.254/latest/meta-data/")]
    )

    assert decision == "BLOCK"
    assert "Ran curl to contact 169.254.169.254" in reason


def test_command_rule_needs_a_reason(tmp_path: Path) -> None:
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
                "command_rules": [
                    {"program": "git", "argument": "*core.fsmonitor*", "score": 80}
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(InvalidPolicyError, match="needs a 'reason'"):
        load_policy(policy_path)