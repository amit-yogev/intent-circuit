# IntentCircuit

Security and evaluation platform for detecting risky multi-step behavior in AI agents.

## The problem

AI agents can read files, send data, modify systems, and perform other actions.
An individual action may appear safe, while a sequence of actions can create a serious security risk.

IntentCircuit analyzes the complete action sequence before deciding whether it should be allowed.

## Current prototype

The current risk engine can:

- Represent actions performed by an AI agent.
- Track resources that were marked as sensitive.
- Detect risky multi-step behavior.
- Calculate a risk score from 0 to 100.
- Return one of four decisions: `ALLOW`, `WARN`, `APPROVAL`, or `BLOCK`.
- Provide a human-readable explanation for every decision.
- Verify the behavior using automated tests.

## Decision levels

| Risk score | Decision | Meaning |
|---|---|---|
| 0-24 | `ALLOW` | The action can continue |
| 25-49 | `WARN` | Continue with a warning |
| 50-74 | `APPROVAL` | Human approval is required |
| 75-100 | `BLOCK` | The action is blocked |

## Example scenarios

- Sharing a public file: `ALLOW`
- Reading a sensitive file: `WARN`
- Deleting a production file: `APPROVAL`
- Reading sensitive data and sending it externally: `BLOCK`

## Configurable security policy

IntentCircuit loads its risk scores and decision thresholds from:

```text
config/default_policy.json
```

Organizations can customize the security policy without modifying the
evaluation engine. For example, increasing the `delete_file` score from
`60` to `80` changes the decision from `APPROVAL` to `BLOCK`.

Example policy:

```json
{
  "scores": {
    "read_sensitive": 30,
    "send_external": 20,
    "delete_file": 60,
    "sensitive_data_exfiltration": 100
  },
  "thresholds": {
    "warn": 25,
    "approval": 50,
    "block": 75
  }
}
```

## Run the demonstration

```powershell
python -m src.intent_circuit.main
```

## Run the automated tests

```powershell
pytest -v
```
## Analyze an external action sequence

IntentCircuit can analyze AI agent actions provided in a JSON file.

Example input:

```text
examples/risky_sequence.json
```

Run the analysis:

```powershell
python -m src.intent_circuit.runner --input examples/risky_sequence.json
```

The command prints the security decision and creates a detailed report at:

```text
reports/latest_report.json
```

The report contains the original actions, risk score, decision, explanation,
and generation time.

## Error handling

IntentCircuit fails closed: when the input is invalid or unknown, it stops and
explains the problem instead of guessing.

| Problem | Example message |
|---|---|
| Missing scenario file | `Error: Scenario file not found: examples/missing.json` |
| Broken JSON | `Error: Scenario file is not valid JSON: ... (line 3, column 5)` |
| Unknown action | `Error: Action #2 has an unknown action name: 'upload_to_cloud'` |
| Missing field | `Error: Action #1 is missing a 'resource'.` |
| Invalid policy | `Error: Policy thresholds must be in order: warn < approval < block.` |

The command exits with code `1` on any of these errors, so other tools and CI
pipelines can detect the failure.

Try it:

```powershell
python -m src.intent_circuit.runner --input examples/unknown_action.json
```