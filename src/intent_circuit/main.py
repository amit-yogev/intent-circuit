from dataclasses import dataclass


@dataclass(frozen=True)
class AgentAction:
    name: str
    resource: str
    sensitive: bool = False
    destination: str | None = None


def decision_from_score(risk_score: int) -> str:
    if risk_score >= 75:
        return "BLOCK"

    if risk_score >= 50:
        return "APPROVAL"

    if risk_score >= 25:
        return "WARN"

    return "ALLOW"


def evaluate_sequence(
    actions: list[AgentAction],
) -> tuple[str, int, str]:
    sensitive_resources: set[str] = set()
    risk_score = 0
    reasons: list[str] = []

    for action in actions:
        if action.name == "read_file" and action.sensitive:
            sensitive_resources.add(action.resource)
            risk_score += 30
            reasons.append(
                f"Sensitive resource was read: {action.resource}."
            )

        elif (
            action.name == "send_file"
            and action.destination == "external"
        ):
            if action.resource in sensitive_resources:
                risk_score = 100
                reasons.append(
                    "Sensitive data was read and then sent externally."
                )
            else:
                risk_score += 20
                reasons.append(
                    "External transfer involved a non-sensitive resource."
                )

        elif action.name == "delete_file":
            risk_score += 60
            reasons.append(
                f"File deletion was requested: {action.resource}."
            )

    risk_score = min(risk_score, 100)
    decision = decision_from_score(risk_score)

    if reasons:
        reason = " ".join(reasons)
    else:
        reason = "No risky actions were detected."

    return decision, risk_score, reason


def print_result(
    scenario_name: str,
    actions: list[AgentAction],
) -> None:
    decision, risk_score, reason = evaluate_sequence(actions)

    print(f"\nScenario: {scenario_name}")
    print(f"Risk score: {risk_score}/100")
    print(f"Decision: {decision}")
    print(f"Reason: {reason}")


def main() -> None:
    safe_actions = [
        AgentAction(
            name="read_file",
            resource="public_report.pdf",
        ),
        AgentAction(
            name="send_file",
            resource="public_report.pdf",
            destination="external",
        ),
    ]

    warning_actions = [
        AgentAction(
            name="read_file",
            resource="employee_salaries.csv",
            sensitive=True,
        ),
    ]

    approval_actions = [
        AgentAction(
            name="delete_file",
            resource="production_database.db",
        ),
    ]

    blocked_actions = [
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

    print_result("Safe file sharing", safe_actions)
    print_result("Sensitive file access", warning_actions)
    print_result("Destructive file deletion", approval_actions)
    print_result("Sensitive data exfiltration", blocked_actions)


if __name__ == "__main__":
    main()