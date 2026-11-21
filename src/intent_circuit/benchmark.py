import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .engine import AgentAction, default_policy_path, evaluate_sequence
from .errors import IntentCircuitError, InvalidScenarioError
from .policy import SecurityPolicy, load_policy
from .runner import parse_action, read_json_file

BENCHMARK_PATH = Path(__file__).resolve().parents[2] / "benchmark" / "cases.json"

CASE_KINDS = frozenset({"escape", "ordinary"})
STOPPED_DECISIONS = frozenset({"APPROVAL", "BLOCK"})


@dataclass(frozen=True)
class BenchmarkCase:
    case_id: str
    kind: str
    origin: str
    description: str
    actions: tuple[AgentAction, ...]


@dataclass(frozen=True)
class CaseResult:
    case: BenchmarkCase
    decision: str
    risk_score: int

    @property
    def stopped(self) -> bool:
        return self.decision in STOPPED_DECISIONS

    @property
    def correct(self) -> bool:
        if self.case.kind == "escape":
            return self.stopped

        return not self.stopped

    @property
    def label(self) -> str:
        if self.case.kind == "escape":
            return "caught" if self.stopped else "MISSED"

        return "FALSE ALARM" if self.stopped else "ok"


def read_case_text(item: dict[str, Any], label: str, key: str) -> str:
    value = item.get(key)

    if not isinstance(value, str) or not value:
        raise InvalidScenarioError(f"{label} needs a '{key}'.")

    return value


def parse_case(item: Any, index: int) -> BenchmarkCase:
    label = f"Case #{index}"

    if not isinstance(item, dict):
        raise InvalidScenarioError(f"{label} must be a JSON object.")

    case_id = read_case_text(item, label, "id")
    label = f"Case '{case_id}'"
    kind = read_case_text(item, label, "kind")

    if kind not in CASE_KINDS:
        raise InvalidScenarioError(
            f"{label}: 'kind' must be one of: {', '.join(sorted(CASE_KINDS))}."
        )

    actions_data = item.get("actions")

    if not isinstance(actions_data, list) or not actions_data:
        raise InvalidScenarioError(f"{label} needs a non-empty 'actions' list.")

    try:
        actions = tuple(
            parse_action(action_data, action_index)
            for action_index, action_data in enumerate(actions_data, start=1)
        )
    except InvalidScenarioError as error:
        raise InvalidScenarioError(f"{label}: {error}") from None

    return BenchmarkCase(
        case_id=case_id,
        kind=kind,
        origin=read_case_text(item, label, "origin"),
        description=read_case_text(item, label, "description"),
        actions=actions,
    )


def load_cases(path: str | Path = BENCHMARK_PATH) -> list[BenchmarkCase]:
    data = read_json_file(Path(path))

    if not isinstance(data, dict) or not isinstance(data.get("cases"), list):
        raise InvalidScenarioError("The benchmark must contain a 'cases' list.")

    cases = [parse_case(item, index) for index, item in enumerate(data["cases"], 1)]

    seen_ids: set[str] = set()

    for case in cases:
        if case.case_id in seen_ids:
            raise InvalidScenarioError(f"Case id '{case.case_id}' is used twice.")

        seen_ids.add(case.case_id)

    return cases


def run_case(case: BenchmarkCase, policy: SecurityPolicy) -> CaseResult:
    decision, risk_score, _ = evaluate_sequence(list(case.actions), policy)
    return CaseResult(case=case, decision=decision, risk_score=risk_score)


def main() -> None:
    try:
        policy = load_policy(default_policy_path())
        cases = load_cases()
    except IntentCircuitError as error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(1)

    print(f"\n{'KIND':<9} {'ORIGIN':<11} {'DECISION':<9} {'SCORE':>5}  {'RESULT':<12} CASE")

    for case in cases:
        result = run_case(case, policy)
        print(
            f"{case.kind:<9} {case.origin:<11} {result.decision:<9} "
            f"{result.risk_score:>5}  {result.label:<12} {case.case_id}"
        )


if __name__ == "__main__":
    main()