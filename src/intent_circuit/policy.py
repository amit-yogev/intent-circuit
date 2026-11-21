import json
import ipaddress
import posixpath
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .errors import InvalidPolicyError

DEFAULT_WRITE_TRIGGER_FILE_SCORE = 60
DEFAULT_TRIGGER_ACTIVATION_SCORE = 40


@dataclass(frozen=True)
class TriggerFile:
    pattern: str
    reason: str
    activated_by: tuple[str, ...] = ()

    def matches(self, path: str) -> bool:
        normalized = posixpath.normpath(path.replace("\\", "/").lower())
        pattern = self.pattern.lower()

        return fnmatchcase(normalized, pattern) or fnmatchcase(
            normalized, "*/" + pattern
        )


def host_of(text: str) -> str:
    cleaned = text.strip().lower()

    if "://" not in cleaned:
        cleaned = "//" + cleaned

    try:
        host = urlsplit(cleaned).hostname or ""
    except ValueError:
        return ""

    return canonical_host(host)


def canonical_host(host: str) -> str:
    try:
        if host.isdigit():
            return str(ipaddress.IPv4Address(int(host)))

        return str(ipaddress.ip_address(host))
    except ValueError:
        return host


@dataclass(frozen=True)
class CommandRule:
    program: str
    argument: str
    reason: str
    score: int

    def find_argument(self, program: str, args: tuple[str, ...]) -> str | None:
        if not fnmatchcase(program, self.program):
            return None

        for arg in args:
            if fnmatchcase(arg.lower(), self.argument):
                return arg

        return None


@dataclass(frozen=True)
class NetworkRule:
    host: str
    reason: str
    score: int

    def matches(self, host: str) -> bool:
        return fnmatchcase(host, self.host)


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
    command_rules: tuple[CommandRule, ...] = ()
    network_rules: tuple[NetworkRule, ...] = ()


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


def read_rule_text(item: dict[str, Any], label: str, key: str) -> str:
    value = item.get(key)

    if not isinstance(value, str) or not value:
        raise InvalidPolicyError(f"{label} needs a '{key}'.")

    return value


def read_command_rules(value: Any) -> tuple[CommandRule, ...]:
    if not isinstance(value, list):
        raise InvalidPolicyError("Policy 'command_rules' must be a list.")

    rules: list[CommandRule] = []

    for index, item in enumerate(value, start=1):
        label = f"Command rule #{index}"

        if not isinstance(item, dict):
            raise InvalidPolicyError(f"{label} must be a JSON object.")

        rules.append(
            CommandRule(
                program=read_rule_text(item, label, "program").lower(),
                argument=read_rule_text(item, label, "argument").lower(),
                reason=read_rule_text(item, label, "reason"),
                score=read_score(item, label, "score"),
            )
        )

    return tuple(rules)


def read_network_rules(value: Any) -> tuple[NetworkRule, ...]:
    if not isinstance(value, list):
        raise InvalidPolicyError("Policy 'network_rules' must be a list.")

    rules: list[NetworkRule] = []

    for index, item in enumerate(value, start=1):
        label = f"Network rule #{index}"

        if not isinstance(item, dict):
            raise InvalidPolicyError(f"{label} must be a JSON object.")

        rules.append(
            NetworkRule(
                host=read_rule_text(item, label, "host").lower(),
                reason=read_rule_text(item, label, "reason"),
                score=read_score(item, label, "score"),
            )
        )

    return tuple(rules)


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
        command_rules=read_command_rules(data.get("command_rules", [])),
        network_rules=read_network_rules(data.get("network_rules", [])),
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