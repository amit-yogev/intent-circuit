import argparse
import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .main import AgentAction, evaluate_sequence
from .policy import SecurityPolicy, load_policy


def load_scenario(
    input_path: str | Path,
) -> tuple[str, list[AgentAction]]:
    path = Path(input_path)

    with path.open(encoding="utf-8") as scenario_file:
        data = json.load(scenario_file)

    scenario_name = data["scenario_name"]

    actions = [
        AgentAction(
            name=action_data["name"],
            resource=action_data["resource"],
            sensitive=action_data.get("sensitive", False),
            destination=action_data.get("destination"),
        )
        for action_data in data["actions"]
    ]

    return scenario_name, actions


def build_report(
    scenario_name: str,
    actions: list[AgentAction],
    policy: SecurityPolicy,
) -> dict[str, Any]:
    decision, risk_score, reason = evaluate_sequence(
        actions,
        policy,
    )

    return {
        "scenario_name": scenario_name,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "risk_score": risk_score,
            "decision": decision,
            "reason": reason,
        },
        "actions": [
            asdict(action)
            for action in actions
        ],
    }


def analyze_scenario(
    input_path: str | Path,
    policy_path: str | Path,
) -> dict[str, Any]:
    scenario_name, actions = load_scenario(input_path)
    policy = load_policy(policy_path)

    return build_report(
        scenario_name,
        actions,
        policy,
    )


def save_report(
    report: dict[str, Any],
    output_path: str | Path,
) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    path.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyze an AI agent action sequence.",
    )

    parser.add_argument(
        "--input",
        required=True,
        type=Path,
        help="Path to the scenario JSON file.",
    )

    parser.add_argument(
        "--policy",
        type=Path,
        default=Path("config/default_policy.json"),
        help="Path to the security policy JSON file.",
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=Path("reports/latest_report.json"),
        help="Path for the generated security report.",
    )

    args = parser.parse_args()

    report = analyze_scenario(
        args.input,
        args.policy,
    )

    save_report(
        report,
        args.output,
    )

    summary = report["summary"]

    print("\nAnalysis complete")
    print(f"Scenario: {report['scenario_name']}")
    print(f"Risk score: {summary['risk_score']}/100")
    print(f"Decision: {summary['decision']}")
    print(f"Reason: {summary['reason']}")
    print(f"Report saved to: {args.output}")


if __name__ == "__main__":
    main()