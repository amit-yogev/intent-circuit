# Roadmap

The goal: detect AI coding agents that try to leave their sandbox, including
the indirect way of writing a file that a host component later runs.

The order is deliberate: first describe richer actions, then detect escape
intent, then prove it with numbers, and only then connect it to a real agent.
A live demo is only convincing once the detection has been measured.

## Done

- [x] Risk engine with a 0–100 score and four decision levels
- [x] Configurable JSON policy, path from an environment variable
- [x] Scenario files and JSON reports
- [x] Input validation and fail-closed error handling
- [x] Automated tests on every pull request
- [x] Architecture document and threat model

## Phase 1: Detect escape intent

- [x] Richer actions: `write_file`, `run_command` with arguments, `network_request`
- [x] A catalog of execution-trigger files (`.vscode/tasks.json`, `.git/hooks`, `.git/config`, `.venv`, CI workflows, agent hook files), each linked to a documented incident
- [x] Provenance: remember which files the agent wrote, and block writing a trigger file followed by running it
- [x] Judge commands by their arguments, not their name: `git -c`, `core.hooksPath`, the Docker socket, cloud metadata, `chmod`, `mount`, `sudo`

## Phase 2: Prove it with numbers

- [x] One scenario per documented escape technique, plus ordinary developer work
- [x] Measure techniques detected and safe actions blocked by mistake
- [x] Compare with a command allowlist that checks names only
- [x] Publish the results, including what is not detected and why

## Phase 3: Real-time guard

- [x] Decide before each step instead of after the fact
- [x] Connect to a real coding agent through a hook that runs before every tool call
- [x] Audit log of every decision
- [ ] Replay command for the audit log

## Phase 4: Demo and packaging

- [ ] Live demo: an agent tries to write `.vscode/tasks.json`, and IntentCircuit stops it
- [ ] Short demo video
- [ ] Install with `pip` and run a single `intentcircuit` command

## Not planned

- A graphical dashboard: a replay command and a video show the same story with less code
- Kernel-level monitoring: runtime tools such as Falco already do this well
- Replacing the sandbox: IntentCircuit is a layer above Docker, not a substitute