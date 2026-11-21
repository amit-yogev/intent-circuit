import json
from pathlib import Path

import pytest

from intent_circuit.benchmark import load_cases, run_case
from intent_circuit.engine import BUILTIN_POLICY_PATH
from intent_circuit.errors import InvalidScenarioError
from intent_circuit.policy import load_policy


@pytest.fixture(scope="module")
def results():
    policy = load_policy(BUILTIN_POLICY_PATH)
    return [run_case(case, policy) for case in load_cases()]


def test_benchmark_has_escapes_and_ordinary_work() -> None:
    kinds = [case.kind for case in load_cases()]

    assert kinds.count("escape") >= 20
    assert kinds.count("ordinary") >= 10


def test_every_documented_escape_is_stopped(results) -> None:
    documented = [r for r in results if r.case.origin == "documented"]

    assert documented
    assert all(r.stopped for r in documented)


def test_known_misses_are_listed(results) -> None:
    missed = {r.case.case_id for r in results if r.label == "MISSED"}

    assert missed == {
        "variant-metadata-ipv6",
        "variant-metadata-decimal-ip",
        "variant-hook-written-by-shell",
        "variant-git-through-env",
        "variant-numeric-setuid",
    }


def test_known_false_alarms_are_listed(results) -> None:
    false_alarms = {r.case.case_id for r in results if r.label == "FALSE ALARM"}

    assert false_alarms == {
        "everyday-add-ci-workflow",
        "everyday-editor-formatting",
    }


def write_benchmark(tmp_path: Path, cases: list) -> Path:
    path = tmp_path / "cases.json"
    path.write_text(json.dumps({"cases": cases}), encoding="utf-8")
    return path


def test_unknown_kind_is_rejected(tmp_path: Path) -> None:
    path = write_benchmark(
        tmp_path,
        [
            {
                "id": "x",
                "kind": "maybe",
                "origin": "variant",
                "description": "x",
                "actions": [{"name": "write_file", "resource": "a.txt"}],
            }
        ],
    )

    with pytest.raises(InvalidScenarioError, match="'kind' must be one of"):
        load_cases(path)


def test_errors_name_the_case(tmp_path: Path) -> None:
    path = write_benchmark(
        tmp_path,
        [
            {
                "id": "broken-case",
                "kind": "escape",
                "origin": "variant",
                "description": "x",
                "actions": [{"name": "teleport", "resource": "a.txt"}],
            }
        ],
    )

    with pytest.raises(InvalidScenarioError, match="Case 'broken-case'"):
        load_cases(path)


def test_duplicate_ids_are_rejected(tmp_path: Path) -> None:
    case = {
        "id": "same",
        "kind": "ordinary",
        "origin": "everyday",
        "description": "x",
        "actions": [{"name": "write_file", "resource": "a.txt"}],
    }

    with pytest.raises(InvalidScenarioError, match="used twice"):
        load_cases(write_benchmark(tmp_path, [case, case]))