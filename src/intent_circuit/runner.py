import argparse
import json
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .errors import IntentCircuitError, InvalidScenarioError, ScenarioFileError
from .main import AgentAction, evaluate_sequence
from .policy import SecurityPolicy, load_policy

KNOWN_ACTIONS = {"read_file", "send_file", "delete_file"}


def read_json_file(path: Path) -> Any:
    try:
        with path.open(encoding="utf-8") as json_file:
            return json.load(json_file)
    except FileNotFoundError:
        raise ScenarioFileError(f"Scenario file not found: {path}") from None
    except json.JSONDecodeError as error:
        raise ScenarioFileError(
            f"Scenario file is not valid JSON: {path} "
            f"(line {error.lineno}, column {error.colno})"
        ) from None


def parse_action(action_data: Any, index: int) -> AgentAction:
    position = f"Action #{index}"

    if not isinstance(action_data, dict):
        raise InvalidScenarioError(f"{position} must be a JSON object.")

    name = action_data.get("name")
    resource = action_data.get("resource")
    sensitive = action_data.get("sensitive", False)
    destination = action_data.get("destination")

    if not isinstance(name, str) or not name:
        raise InvalidScenarioError(f"{position} is missing a 'name'.")

    if name not in KNOWN_ACTIONS:
        raise InvalidScenarioError(
            f"{position} has an unknown action name: '{name}'. "
            f"Known actions: {', '.join(sorted(KNOWN_ACTIONS))}."
        )

    if not isinstance(resource, str) or not resource:
        raise InvalidScenarioError(f"{position} is missing a 'resource'.")

    if not isinstance(sensitive, bool):
        raise InvalidScenarioError(
            f"{position}: 'sensitive' must be true or false."
        )

    if destination is not None and not isinstance(destination, str):
        raise InvalidScenarioError(f"{position}: 'destination' must be text.")

    return AgentAction(
        name=name,
        resource=resource,
        sensitive=sensitive,
        destination=destination,
    )


def load_scenario(
    input_path: str | Path,
) -> tuple[str, list[AgentAction]]:
    data = read_json_file(Path(input_path))

    if not isinstance(data, dict):
        raise InvalidScenarioError("The scenario must be a JSON object.")

    scenario_name = data.get("scenario_name")
    if not isinstance(scenario_name, str) or not scenario_name:
        raise InvalidScenarioError("The scenario is missing a 'scenario_name'.")

    actions_data = data.get("actions")
    if not isinstance(actions_data, list) or not actions_data:
        raise InvalidScenarioError(
            "The scenario must contain a non-empty 'actions' list."
        )

    actions = [
        parse_action(action_data, index)
        for index, action_data in enumerate(actions_data, start=1)
    ]

    return scenario_name, actions


def build_report(
    scenario_name: str,
    actions: list[AgentAction],
    policy: SecurityPolicy,
) -> dict[str, Any]:
    decision, risk_score, reason = evaluate_sequence(actions, policy)

    return {
        "scenario_name": scenario_name,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "risk_score": risk_score,
            "decision": decision,
            "reason": reason,
        },
        "actions": [asdict(action) for action in actions],
    }


def analyze_scenario(
    input_path: str | Path,
    policy_path: str | Path,
) -> dict[str, Any]:
    scenario_name, actions = load_scenario(input_path)
    policy = load_policy(policy_path)

    return build_report(scenario_name, actions, policy)


def save_report(
    report: dict[str, Any],
    output_path: str | Path,
) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    path.write_text(json.dumps(report, indent=2), encoding="utf-8")


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

    try:
        report = analyze_scenario(args.input, args.policy)
        save_report(report, args.output)
    except IntentCircuitError as error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(1)

    summary = report["summary"]

    print("\nAnalysis complete")
    print(f"Scenario: {report['scenario_name']}")
    print(f"Risk score: {summary['risk_score']}/100")
    print(f"Decision: {summary['decision']}")
    print(f"Reason: {summary['reason']}")
    print(f"Report saved to: {args.output}")


if __name__ == "__main__":
    main()