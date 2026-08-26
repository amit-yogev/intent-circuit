import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class SecurityPolicy:
    read_sensitive_score: int
    send_external_score: int
    delete_file_score: int
    sensitive_data_exfiltration_score: int
    warn_threshold: int
    approval_threshold: int
    block_threshold: int


def load_policy(policy_path: str | Path) -> SecurityPolicy:
    path = Path(policy_path)

    with path.open(encoding="utf-8") as policy_file:
        data = json.load(policy_file)

    scores = data["scores"]
    thresholds = data["thresholds"]

    return SecurityPolicy(
        read_sensitive_score=scores["read_sensitive"],
        send_external_score=scores["send_external"],
        delete_file_score=scores["delete_file"],
        sensitive_data_exfiltration_score=(
            scores["sensitive_data_exfiltration"]
        ),
        warn_threshold=thresholds["warn"],
        approval_threshold=thresholds["approval"],
        block_threshold=thresholds["block"],
    )