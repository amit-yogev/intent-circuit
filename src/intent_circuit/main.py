from dataclasses import dataclass


@dataclass(frozen=True)
class AgentAction:
    name: str
    resource: str
    sensitive: bool = False
    destination: str | None = None


def evaluate_sequence(actions: list[AgentAction]) -> tuple[str, str]:
    sensitive_resources: set[str] = set()

    for action in actions:
        if action.name == "read_file" and action.sensitive:
            sensitive_resources.add(action.resource)

        if (
            action.name == "send_file"
            and action.resource in sensitive_resources
            and action.destination == "external"
        ):
            return "BLOCK", "Sensitive data was read and then sent externally."

    return "ALLOW", "No dangerous action sequence was detected."


def main() -> None:
    actions = [
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

    decision, reason = evaluate_sequence(actions)

    print(f"Decision: {decision}")
    print(f"Reason: {reason}")


if __name__ == "__main__":
    main()