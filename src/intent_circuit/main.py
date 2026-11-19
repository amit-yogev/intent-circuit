from .engine import AgentAction, default_policy_path, evaluate_sequence
from .policy import SecurityPolicy, load_policy


def print_result(
    scenario_name: str,
    actions: list[AgentAction],
    policy: SecurityPolicy,
) -> None:
    decision, risk_score, reason = evaluate_sequence(actions, policy)

    print(f"\nScenario: {scenario_name}")
    print(f"Risk score: {risk_score}/100")
    print(f"Decision: {decision}")
    print(f"Reason: {reason}")


def main() -> None:
    policy = load_policy(default_policy_path())

    scenarios = {
        "Safe local file access": [
            AgentAction(name="read_file", resource="public_report.pdf"),
        ],
        "External file sharing": [
            AgentAction(
                name="send_file",
                resource="public_report.pdf",
                destination="external",
            ),
        ],
        "Destructive file deletion": [
            AgentAction(name="delete_file", resource="production_database.db"),
        ],
        "Sensitive data exfiltration": [
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
        ],
    }

    for scenario_name, actions in scenarios.items():
        print_result(scenario_name, actions, policy)


if __name__ == "__main__":
    main()