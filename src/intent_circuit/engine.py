import os
from dataclasses import dataclass
from pathlib import Path

from .policy import SecurityPolicy, TriggerFile, load_policy

POLICY_PATH_ENV_VAR = "INTENTCIRCUIT_POLICY_PATH"

PROJECT_ROOT = Path(__file__).resolve().parents[2]
BUILTIN_POLICY_PATH = PROJECT_ROOT / "config" / "default_policy.json"

KNOWN_ACTIONS = frozenset(
    {
        "read_file",
        "send_file",
        "delete_file",
        "write_file",
        "run_command",
        "network_request",
    }
)


def default_policy_path() -> Path:
    configured_path = os.environ.get(POLICY_PATH_ENV_VAR)

    if configured_path:
        return Path(configured_path)

    return BUILTIN_POLICY_PATH


@dataclass(frozen=True)
class AgentAction:
    name: str
    resource: str
    sensitive: bool = False
    destination: str | None = None
    args: tuple[str, ...] = ()


def decision_from_score(
    risk_score: int,
    policy: SecurityPolicy,
) -> str:
    if risk_score >= policy.block_threshold:
        return "BLOCK"

    if risk_score >= policy.approval_threshold:
        return "APPROVAL"

    if risk_score >= policy.warn_threshold:
        return "WARN"

    return "ALLOW"


def find_trigger_file(
    path: str,
    trigger_files: tuple[TriggerFile, ...],
) -> TriggerFile | None:
    for trigger_file in trigger_files:
        if trigger_file.matches(path):
            return trigger_file

    return None


def evaluate_sequence(
    actions: list[AgentAction],
    policy: SecurityPolicy | None = None,
) -> tuple[str, int, str]:
    active_policy = policy or load_policy(default_policy_path())

    sensitive_resources: set[str] = set()
    reasons: list[str] = []
    risk_score = 0

    for action in actions:
        if action.name == "read_file" and action.sensitive:
            sensitive_resources.add(action.resource)
            risk_score += active_policy.read_sensitive_score
            reasons.append(f"Sensitive resource was read: {action.resource}.")

        if action.name == "send_file" and action.destination == "external":
            if action.resource in sensitive_resources:
                risk_score = max(
                    risk_score,
                    active_policy.sensitive_data_exfiltration_score,
                )
                reasons.append(
                    "Sensitive data was read and then sent externally."
                )
            else:
                risk_score += active_policy.send_external_score
                reasons.append("A resource was sent externally.")

        if action.name == "delete_file":
            risk_score += active_policy.delete_file_score
            reasons.append(f"File deletion was requested: {action.resource}.")

        if action.name == "write_file":
            trigger_file = find_trigger_file(
                action.resource,
                active_policy.trigger_files,
            )

            if trigger_file is not None:
                risk_score += active_policy.write_trigger_file_score
                reasons.append(
                    f"Wrote an execution-trigger file: {action.resource} "
                    f"({trigger_file.reason})."
                )

    risk_score = min(risk_score, 100)
    decision = decision_from_score(risk_score, active_policy)

    reason = (
        " ".join(reasons)
        if reasons
        else "No dangerous action sequence was detected."
    )

    return decision, risk_score, reason