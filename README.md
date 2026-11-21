# IntentCircuit

![Tests](https://github.com/amit-yogev/intent-circuit/actions/workflows/tests.yml/badge.svg)

**A security layer that watches what AI coding agents do, and decides when to stop them, when a
sequence of allowed actions adds up to something dangerous.**

## Why

AI agents now read files, run commands and send data on their own. Sandboxes
and permission lists judge one action at a time.

In July 2026, researchers showed sandbox escapes in Cursor, Codex, Gemini CLI
and Antigravity where every single step was allowed: the agent wrote an
ordinary-looking file, such as a VS Code task or a Git setting, and a component
outside the sandbox later ran it.

IntentCircuit looks at the whole sequence of actions and the intent behind it.

## What it does today

- Evaluates an ordered sequence of agent actions and remembers earlier steps
- Calculates a risk score from 0 to 100 and returns `ALLOW`, `WARN`, `APPROVAL` or `BLOCK`, with an explanation
- Detects sensitive data being read and then sent outside the organization
- Loads its rules from a JSON policy that each organization can change without touching the code
- Fails closed: unknown or malformed input is rejected, never silently allowed
- Understands file writes, commands with their arguments, and network requests
- Flags writes to execution-trigger files, such as `.vscode/tasks.json`, Git hooks and CI workflows, for human approval
- Automated tests run on every pull request

**Status:** early prototype. Detecting sandbox-escape intent (execution-trigger
files, command arguments, the Docker socket, cloud metadata) is the next
milestone. See the [roadmap](ROADMAP.md).

## Example

Input (`examples/risky_sequence.json`):

```json
{
  "scenario_name": "Potential employee data leak",
  "actions": [
    {"name": "read_file", "resource": "employee_salaries.csv", "sensitive": true},
    {"name": "send_file", "resource": "employee_salaries.csv", "destination": "external"}
  ]
}
```

Output:

```text
Analysis complete 
Scenario: Potential employee data leak
Risk score: 100/100
Decision: BLOCK
Reason: Sensitive resource was read: employee_salaries.csv. Sensitive data was read and then sent externally.
Report saved to: reports\latest_report.json
```

## Quick start

Tested with Python 3.13.

```powershell
git clone https://github.com/amit-yogev/intent-circuit.git
cd intent-circuit
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
```

On macOS or Linux, activate the environment with `source .venv/bin/activate`.
If Windows blocks the activation script, run
`Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned` first.

Run the tests:

```powershell
pytest -v
```

Run the demonstration scenarios:

```powershell
python -m src.intent_circuit.main
```

Analyze a scenario file and save a report to `reports/latest_report.json`:

```powershell
python -m src.intent_circuit.runner --input examples/risky_sequence.json
```

## Decision levels

| Risk score | Decision | Meaning |
|---|---|---|
| 0–24 | `ALLOW` | The action continues |
| 25–49 | `WARN` | The action continues with a warning |
| 50–74 | `APPROVAL` | A person must approve it |
| 75–100 | `BLOCK` | The action is blocked |

## Configuration

Scores and thresholds live in `config/default_policy.json`. Changing the
`delete_file` score from `60` to `80`, for example, turns `APPROVAL` into
`BLOCK` without any code change.

To use a different policy file, set an environment variable:

```powershell
$env:INTENTCIRCUIT_POLICY_PATH = "config/my_policy.json"
```

## Error handling

| Problem | Example message |
|---|---|
| Missing scenario file | `Error: Scenario file not found: examples/missing.json` |
| Unknown action | `Error: Action #2 has an unknown action name: 'upload_to_cloud'` |
| Invalid policy | `Error: Policy thresholds must be in order: warn < approval < block.` |

Every error exits with code `1`, so other tools and CI pipelines can detect it.

## Project structure

| File | Responsibility |
|---|---|
| `src/intent_circuit/engine.py` | Risk engine: evaluates an action sequence and returns a decision |
| `src/intent_circuit/policy.py` | Loads and validates the security policy |
| `src/intent_circuit/runner.py` | Command-line tool: reads a scenario file and saves a report |
| `src/intent_circuit/errors.py` | Error types for invalid scenarios and policies |
| `src/intent_circuit/main.py` | Demonstration scenarios |
| `tests/` | Automated tests |
| `.github/workflows/tests.yml` | Runs the tests on every pull request |

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md): requirements, design, decisions and trade-offs, threat model
- [ROADMAP.md](ROADMAP.md): what comes next and why

## License

MIT