# Architecture

```
┌─────────────────────────────────────────┐
│  CLI (typer + rich)                       │
├─────────────────────────────────────────┤
│  Orchestrator  (core/orchestrator.py)     │
│   plan → validate → run → parse → audit   │
├──────────────┬──────────────────────────┤
│ Planner      │  State (core/state.py)     │
│ (core/llm.py)│  hosts/services/creds/…    │
├──────────────┴──────────────────────────┤
│  Safety (safety/)  scope · validator · audit │
├─────────────────────────────────────────┤
│  Tool adapters (tools/)  run + parse→struct │
└─────────────────────────────────────────┘
```

## The loop

Each `Orchestrator.step()`:

1. Build a compact state summary (no raw output).
2. **Planner** decides the next action + rationale (Claude, or heuristic offline).
3. Adapter builds an argv command.
4. **Validator** checks it: binary allowlist, no shell metacharacters, scope,
   risk threshold. Blocked → skipped and logged. Above threshold → confirmation.
5. Adapter runs the command and **parses** the output into `EngagementState`.
6. Everything is written to the append-only **audit log**; state is persisted.

## Why the split

- **Deterministic core** (parsing, scope, state) is testable and reproducible —
  it never hallucinates a port or a target.
- **LLM** handles the fuzzy part: what to do next and why. Its output is always
  validated in code before anything runs.

## Key modules

| Module | Responsibility |
|---|---|
| `core/state.py` | Typed records for hosts, services, creds, findings, history |
| `core/orchestrator.py` | The plan→validate→run→parse→audit loop |
| `core/llm.py` | Claude planner + offline heuristic fallback |
| `core/config.py` | Engagement YAML (scope, mode, autonomy) |
| `safety/scope.py` | CIDR/domain allowlist + target extraction |
| `safety/validator.py` | Command gate + Risk classifier |
| `safety/audit.py` | Append-only JSONL trail |
| `tools/base.py` | Adapter contract (`build_command` + `parse`) |
| `tools/nmap.py` | Reference adapter (XML → struct) |
