import json
from pathlib import Path

from intent_circuit.runner import analyze_scenario, save_report


def test_analyzes_json_scenario_and_saves_report(
    tmp_path: Path,
) -> None:
    input_path = tmp_path / "scenario.json"
    output_path = tmp_path / "report.json"

    scenario_data = {
        "scenario_name": "Test data leak",
        "actions": [
            {
                "name": "read_file",
                "resource": "customers.csv",
                "sensitive": True,
            },
            {
                "name": "send_file",
                "resource": "customers.csv",
                "destination": "external",
            },
        ],
    }

    input_path.write_text(
        json.dumps(scenario_data),
        encoding="utf-8",
    )

    report = analyze_scenario(
        input_path,
        Path("config/default_policy.json"),
    )

    save_report(report, output_path)

    assert report["scenario_name"] == "Test data leak"
    assert report["summary"]["risk_score"] == 100
    assert report["summary"]["decision"] == "BLOCK"
    assert output_path.exists()

    saved_report = json.loads(
        output_path.read_text(encoding="utf-8")
    )

    assert saved_report["summary"]["decision"] == "BLOCK"
    assert len(saved_report["actions"]) == 2