import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .engine import AgentAction, default_policy_path, evaluate_sequence, program_name
from .errors import IntentCircuitError, InvalidScenarioError
from .policy import SecurityPolicy, load_policy
from .runner import parse_action, read_json_file

BENCHMARK_PATH = Path(__file__).resolve().parents[2] / "benchmark" / "cases.json"

CASE_KINDS = frozenset({"escape", "ordinary"})
STOPPED_DECISIONS = frozenset({"APPROVAL", "BLOCK"})
ORIGINS = ("documented", "variant", "everyday", "held-out", "held-out-everyday")

# The baseline is a permission list that checks program names only, the kind
# of control that the 2026 escapes went through. It allows the programs that
# the ordinary cases need, and nothing else.
BASELINE_ALLOWED_PROGRAMS = frozenset(
    {"build.sh", "chmod", "curl", "docker", "git", "ls", "pip", "pytest"}
)


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
        return is_correct(self.case.kind, self.stopped)

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


def baseline_stops(case: BenchmarkCase) -> bool:
    return any(
        action.name == "run_command"
        and program_name(action.resource) not in BASELINE_ALLOWED_PROGRAMS
        for action in case.actions
    )


def is_correct(kind: str, stopped: bool) -> bool:
    return stopped if kind == "escape" else not stopped


def summarize(results: list[CaseResult]) -> dict[str, dict[str, int]]:
    summary: dict[str, dict[str, int]] = {}

    for origin in ORIGINS:
        group = [r for r in results if r.case.origin == origin]
        summary[origin] = {
            "total": len(group),
            "intent_circuit": sum(r.correct for r in group),
            "baseline": sum(
                is_correct(r.case.kind, baseline_stops(r.case)) for r in group
            ),
        }

    return summary


def score_text(part: int, whole: int) -> str:
    if whole == 0:
        return "-"

    return f"{part}/{whole} ({round(100 * part / whole)}%)"


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

    results = [run_case(case, policy) for case in cases]

    print(f"\n{'KIND':<9} {'ORIGIN':<17} {'DECISION':<9} {'SCORE':>5}  {'RESULT':<12} CASE")

    for result in results:
        case = result.case
        print(
            f"{case.kind:<9} {case.origin:<17} {result.decision:<9} "
            f"{result.risk_score:>5}  {result.label:<12} {case.case_id}"
        )

    goals = {
        "documented": "escapes stopped",
        "variant": "escapes stopped",
        "everyday": "ordinary tasks allowed",
        "held-out": "escapes stopped",
        "held-out-everyday": "ordinary tasks allowed",
    }

    print(f"\n{'ORIGIN':<17} {'GOAL':<23} {'INTENTCIRCUIT':>14} {'NAME-ONLY LIST':>15}")

    for origin, counts in summarize(results).items():
        ours = score_text(counts["intent_circuit"], counts["total"])
        base = score_text(counts["baseline"], counts["total"])
        print(f"{origin:<17} {goals[origin]:<23} {ours:>14} {base:>15}")


if __name__ == "__main__":
    main()