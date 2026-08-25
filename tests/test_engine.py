from intent_circuit.main import AgentAction, evaluate_sequence


def test_allows_safe_file_sharing() -> None:
    actions = [
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

    decision, reason = evaluate_sequence(actions)

    assert decision == "ALLOW"
    assert reason == "No dangerous action sequence was detected."


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

    decision, reason = evaluate_sequence(actions)

    assert decision == "BLOCK"
    assert "sent externally" in reason