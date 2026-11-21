import json
import os
import re
import shlex
import sys
import tempfile
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .engine import AgentAction, default_policy_path, evaluate_sequence
from .policy import SecurityPolicy, load_policy

COMMAND_TOOLS = frozenset({"Bash", "PowerShell"})
WRITE_TOOLS = frozenset({"Write", "Edit", "MultiEdit"})
COMMAND_SEPARATORS = frozenset({"&&", "||", ";", "|", "&"})

STATE_DIR_ENV_VAR = "INTENTCIRCUIT_STATE_DIR"
SAFE_SESSION_ID = re.compile(r"[A-Za-z0-9_-]{1,128}")

# Only risky decisions are answered. Answering "allow" would skip
# Claude Code's own permission checks, so every other decision stays silent.
PERMISSION_FOR_DECISION = {"BLOCK": "deny", "APPROVAL": "ask"}


def split_commands(command: str) -> list[list[str]]:
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        tokens = list(lexer)
    except ValueError:
        tokens = command.split()

    commands: list[list[str]] = [[]]

    for token in tokens:
        if token in COMMAND_SEPARATORS:
            commands.append([])
        else:
            commands[-1].append(token)

    return [words for words in commands if words]


def actions_from_tool_call(
    tool_name: str, tool_input: dict[str, Any]
) -> list[AgentAction]:
    if tool_name in COMMAND_TOOLS:
        return [
            AgentAction(
                name="run_command", resource=words[0], args=tuple(words[1:])
            )
            for words in split_commands(str(tool_input.get("command", "")))
        ]

    if tool_name in WRITE_TOOLS:
        path = str(tool_input.get("file_path", ""))
        return [AgentAction(name="write_file", resource=path)]

    if tool_name == "Read":
        path = str(tool_input.get("file_path", ""))
        return [AgentAction(name="read_file", resource=path)]

    if tool_name == "WebFetch":
        url = str(tool_input.get("url", ""))
        return [AgentAction(name="network_request", resource=url)]

    return []


def state_dir() -> Path:
    configured = os.environ.get(STATE_DIR_ENV_VAR)

    if configured:
        return Path(configured)

    return Path(tempfile.gettempdir()) / "intent-circuit"


def history_path(session_id: str) -> Path:
    if not SAFE_SESSION_ID.fullmatch(session_id):
        raise ValueError("the session id contains unexpected characters")

    return state_dir() / f"{session_id}.json"


def load_history(path: Path) -> list[AgentAction]:
    if not path.exists():
        return []

    items = json.loads(path.read_text(encoding="utf-8"))
    return [AgentAction(**{**item, "args": tuple(item["args"])}) for item in items]


def save_history(path: Path, history: list[AgentAction]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps([asdict(a) for a in history]), encoding="utf-8")


def decide(
    history: list[AgentAction],
    new_actions: list[AgentAction],
    policy: SecurityPolicy,
) -> tuple[str, int, str]:
    _, _, before_reason = evaluate_sequence(history, policy)
    decision, risk_score, after_reason = evaluate_sequence(
        history + new_actions, policy
    )

    if after_reason == before_reason:
        return "ALLOW", risk_score, "No new risk."

    return decision, risk_score, after_reason.removeprefix(before_reason).strip()


def hook_response(decision: str, reason: str) -> dict[str, Any] | None:
    permission = PERMISSION_FOR_DECISION.get(decision)

    if permission is None:
        return None

    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": permission,
            "permissionDecisionReason": f"IntentCircuit {decision}: {reason}",
        }
    }


def write_audit_log(entry: dict[str, Any]) -> None:
    path = state_dir() / "audit.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("a", encoding="utf-8") as log:
        log.write(json.dumps(entry) + "\n")


def handle_call(call: dict[str, Any], policy: SecurityPolicy) -> dict[str, Any] | None:
    session_id = call.get("session_id")
    tool_name = call.get("tool_name")
    tool_input = call.get("tool_input")

    if not isinstance(session_id, str) or not isinstance(tool_name, str):
        raise ValueError("the call needs a 'session_id' and a 'tool_name'")

    if not isinstance(tool_input, dict):
        raise ValueError("the call needs a 'tool_input' object")

    new_actions = actions_from_tool_call(tool_name, tool_input)

    if not new_actions:
        return None

    path = history_path(session_id)
    history = load_history(path)
    decision, risk_score, reason = decide(history, new_actions, policy)

    if decision != "BLOCK":
        save_history(path, history + new_actions)

    write_audit_log(
        {
            "time": datetime.now(timezone.utc).isoformat(),
            "session_id": session_id,
            "tool_name": tool_name,
            "decision": decision,
            "risk_score": risk_score,
            "reason": reason,
        }
    )

    return hook_response(decision, reason)


def main() -> None:
    try:
        call = json.loads(sys.stdin.buffer.read().decode("utf-8"))

        if not isinstance(call, dict):
            raise ValueError("the call must be a JSON object")

        response = handle_call(call, load_policy(default_policy_path()))
    except Exception as error:
        response = hook_response(
            "BLOCK", f"the action could not be checked ({error}), so it was blocked."
        )

    if response is not None:
        print(json.dumps(response))


if __name__ == "__main__":
    main()