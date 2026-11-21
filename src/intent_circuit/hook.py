import shlex
from typing import Any

from .engine import AgentAction

COMMAND_TOOLS = frozenset({"Bash", "PowerShell"})
WRITE_TOOLS = frozenset({"Write", "Edit", "MultiEdit"})
COMMAND_SEPARATORS = frozenset({"&&", "||", ";", "|", "&"})


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