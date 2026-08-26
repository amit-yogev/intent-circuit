from dataclasses import dataclass
from pathlib import Path

from .policy import SecurityPolicy, load_policy


DEFAULT_POLICY_PATH = (
    Path(__file__).resolve().parents[2]
    / "config"
    / "default_policy.json"
)


@dataclass(frozen=True)
class AgentAction:
    name: str
    resource: str
    sensitive: bool = False
    destination: str | None = None


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


def evaluate_sequence(
    actions: list[AgentAction],
    policy: SecurityPolicy | None = None,
) -> tuple[str, int, str]:
    active_policy = policy or load_policy(DEFAULT_POLICY_PATH)

    sensitive_resources: set[str] = set()
    reasons: list[str] = []
    risk_score = 0

    for action in actions:
        if action.name == "read_file" and action.sensitive:
            sensitive_resources.add(action.resource)
            risk_score += active_policy.read_sensitive_score
            reasons.append(
                f"Sensitive resource was read: {action.resource}."
            )

        if (
            action.name == "send_file"
            and action.destination == "external"
        ):
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
            reasons.append(
                f"File deletion was requested: {action.resource}."
            )

    risk_score = min(risk_score, 100)
    decision = decision_from_score(risk_score, active_policy)

    reason = (
        " ".join(reasons)
        if reasons
        else "No dangerous action sequence was detected."
    )

    return decision, risk_score, reason


def print_result(
    scenario_name: str,
    actions: list[AgentAction],
    policy: SecurityPolicy,
) -> None:
    decision, risk_score, reason = evaluate_sequence(
        actions,
        policy,
    )

    print(f"\nScenario: {scenario_name}")
    print(f"Risk score: {risk_score}/100")
    print(f"Decision: {decision}")
    print(f"Reason: {reason}")


def main() -> None:
    policy = load_policy(DEFAULT_POLICY_PATH)

    safe_actions = [
        AgentAction(
            name="read_file",
            resource="public_report.pdf",
        ),
    ]

    external_sharing_actions = [
        AgentAction(
            name="send_file",
            resource="public_report.pdf",
            destination="external",
        ),
    ]

    deletion_actions = [
        AgentAction(
            name="delete_file",
            resource="production_database.db",
        ),
    ]

    risky_actions = [
        AgentAction(
            name="read_file",
            resource="employee_salaries.csv",
            sensitive=True,
        ),
        AgentAction(
            name="send_file",
            resource="employee_salaries.csv",
            destination="external",
        ),
    ]

    print_result("Safe local file access", safe_actions, policy)
    print_result(
        "External file sharing",
        external_sharing_actions,
        policy,
    )
    print_result(
        "Destructive file deletion",
        deletion_actions,
        policy,
    )
    print_result(
        "Sensitive data exfiltration",
        risky_actions,
        policy,
    )


if __name__ == "__main__":
    main()