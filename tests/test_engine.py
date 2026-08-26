from intent_circuit.main import AgentAction, evaluate_sequence


def test_allows_safe_file_sharing() -> None:
    actions = [
        AgentAction(
            name="send_file",
            resource="public_report.pdf",
            destination="external",
        ),
    ]

    decision, risk_score, _ = evaluate_sequence(actions)

    assert decision == "ALLOW"
    assert risk_score == 20


def test_warns_about_sensitive_file_access() -> None:
    actions = [
        AgentAction(
            name="read_file",
            resource="employee_salaries.csv",
            sensitive=True,
        ),
    ]

    decision, risk_score, _ = evaluate_sequence(actions)

    assert decision == "WARN"
    assert risk_score == 30


def test_requires_approval_for_file_deletion() -> None:
    actions = [
        AgentAction(
            name="delete_file",
            resource="production_database.db",
        ),
    ]

    decision, risk_score, _ = evaluate_sequence(actions)

    assert decision == "APPROVAL"
    assert risk_score == 60


def test_blocks_sensitive_data_exfiltration() -> None:
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

    decision, risk_score, _ = evaluate_sequence(actions)

    assert decision == "BLOCK"
    assert risk_score == 100