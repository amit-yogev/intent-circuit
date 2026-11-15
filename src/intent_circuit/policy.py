import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import InvalidPolicyError


@dataclass(frozen=True)
class SecurityPolicy:
    read_sensitive_score: int
    send_external_score: int
    delete_file_score: int
    sensitive_data_exfiltration_score: int
    warn_threshold: int
    approval_threshold: int
    block_threshold: int


def read_score(section: dict[str, Any], section_name: str, key: str) -> int:
    value = section.get(key)

    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidPolicyError(
            f"Policy value '{section_name}.{key}' must be a whole number."
        )

    if not 0 <= value <= 100:
        raise InvalidPolicyError(
            f"Policy value '{section_name}.{key}' must be between 0 and 100."
        )

    return value


def load_policy(policy_path: str | Path) -> SecurityPolicy:
    path = Path(policy_path)

    try:
        with path.open(encoding="utf-8") as policy_file:
            data = json.load(policy_file)
    except FileNotFoundError:
        raise InvalidPolicyError(f"Policy file not found: {path}") from None
    except json.JSONDecodeError as error:
        raise InvalidPolicyError(
            f"Policy file is not valid JSON: {path} "
            f"(line {error.lineno}, column {error.colno})"
        ) from None

    if not isinstance(data, dict):
        raise InvalidPolicyError("The policy must be a JSON object.")

    scores = data.get("scores")
    thresholds = data.get("thresholds")

    if not isinstance(scores, dict):
        raise InvalidPolicyError("The policy is missing a 'scores' section.")

    if not isinstance(thresholds, dict):
        raise InvalidPolicyError("The policy is missing a 'thresholds' section.")

    policy = SecurityPolicy(
        read_sensitive_score=read_score(scores, "scores", "read_sensitive"),
        send_external_score=read_score(scores, "scores", "send_external"),
        delete_file_score=read_score(scores, "scores", "delete_file"),
        sensitive_data_exfiltration_score=read_score(
            scores, "scores", "sensitive_data_exfiltration"
        ),
        warn_threshold=read_score(thresholds, "thresholds", "warn"),
        approval_threshold=read_score(thresholds, "thresholds", "approval"),
        block_threshold=read_score(thresholds, "thresholds", "block"),
    )

    if not (
        policy.warn_threshold
        < policy.approval_threshold
        < policy.block_threshold
    ):
        raise InvalidPolicyError(
            "Policy thresholds must be in order: warn < approval < block."
        )

    return policy