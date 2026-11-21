import json
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

from .errors import InvalidPolicyError

DEFAULT_WRITE_TRIGGER_FILE_SCORE = 60
DEFAULT_TRIGGER_ACTIVATION_SCORE = 40


@dataclass(frozen=True)
class TriggerFile:
    pattern: str
    reason: str
    activated_by: tuple[str, ...] = ()

    def matches(self, path: str) -> bool:
        normalized = path.replace("\\", "/").lower()

        if normalized.startswith("./"):
            normalized = normalized[2:]

        pattern = self.pattern.lower()

        return fnmatchcase(normalized, pattern) or fnmatchcase(
            normalized, "*/" + pattern
        )


@dataclass(frozen=True)
class SecurityPolicy:
    read_sensitive_score: int
    send_external_score: int
    delete_file_score: int
    sensitive_data_exfiltration_score: int
    warn_threshold: int
    approval_threshold: int
    block_threshold: int
    write_trigger_file_score: int = DEFAULT_WRITE_TRIGGER_FILE_SCORE
    trigger_activation_score: int = DEFAULT_TRIGGER_ACTIVATION_SCORE
    trigger_files: tuple[TriggerFile, ...] = ()


def read_score(
    section: dict[str, Any],
    section_name: str,
    key: str,
    default: int | None = None,
) -> int:
    value = section.get(key, default)

    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidPolicyError(
            f"Policy value '{section_name}.{key}' must be a whole number."
        )

    if not 0 <= value <= 100:
        raise InvalidPolicyError(
            f"Policy value '{section_name}.{key}' must be between 0 and 100."
        )

    return value


def read_trigger_files(value: Any) -> tuple[TriggerFile, ...]:
    if not isinstance(value, list):
        raise InvalidPolicyError("Policy 'trigger_files' must be a list.")

    trigger_files: list[TriggerFile] = []

    for index, item in enumerate(value, start=1):
        if not isinstance(item, dict):
            raise InvalidPolicyError(
                f"Trigger file #{index} must be a JSON object."
            )

        pattern = item.get("pattern")
        reason = item.get("reason")

        if not isinstance(pattern, str) or not pattern:
            raise InvalidPolicyError(f"Trigger file #{index} needs a 'pattern'.")

        if not isinstance(reason, str) or not reason:
            raise InvalidPolicyError(f"Trigger file #{index} needs a 'reason'.")

        activated_by = item.get("activated_by", [])

        if not isinstance(activated_by, list) or not all(
            isinstance(program, str) and program for program in activated_by
        ):
            raise InvalidPolicyError(
                f"Trigger file #{index}: 'activated_by' must be a list of "
                "program names."
            )

        trigger_files.append(
            TriggerFile(
                pattern=pattern,
                reason=reason,
                activated_by=tuple(program.lower() for program in activated_by),
            )
        )

    return tuple(trigger_files)


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
        write_trigger_file_score=read_score(
            scores,
            "scores",
            "write_trigger_file",
            default=DEFAULT_WRITE_TRIGGER_FILE_SCORE,
        ),
        trigger_activation_score=read_score(
            scores,
            "scores",
            "trigger_activation",
            default=DEFAULT_TRIGGER_ACTIVATION_SCORE,
        ),
        trigger_files=read_trigger_files(data.get("trigger_files", [])),
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