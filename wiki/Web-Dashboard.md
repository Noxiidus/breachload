# Web Dashboard

A live, WebSocket-backed view of the engagement in a browser. Useful for
long autonomous runs, demos, and confirming decisions on your phone.

## Install & start

```bash
pip install -e '.[web]'                 # FastAPI + uvicorn
breachload serve engagements/<cfg>      # http://localhost:8000
```

## What you get

- **Live stream** (top-left) — every `emit()` from the orchestrator lands as
  a color-tagged line (run / note / finding / blocked / phase / flag).
- **Hosts & services** table — refreshes as the state grows.
- **Findings** — one row per finding with:
  - Severity color-coded (`critical`, `high`, `medium`, `low`, `info`)
  - `[CONFIRMED]` / suspected badge
  - `(N confirmed / M total)` counter next to the section header
  - A **severity filter** (`all` / `confirmed only` / `critical+high`)
- **Confirmation modal** — when an intrusive action needs approval, the
  page pops a modal with the exact argv; approve / deny from the browser.
- **Stop engagement** button — kills the current run cleanly.

## Confirmation flow

The orchestrator's `confirm` gate is bridged into the WebSocket hub. When a
tool waits for approval, a `confirm` event arrives with the command; you
click Approve or Deny in the browser, and the engine continues (or the
action is blocked and recorded as `approved=False` in state).

Approving a specific action approves it for this scope only — never
generalises to later actions.

## Live state via WS + polling fallback

The dashboard receives the full state over the WebSocket after every mutation
(atomic snapshot). If the socket drops it polls `/api/state` every 3s as a
fallback. You never miss a state change.

## Endpoints

- `GET /` — the dashboard page (self-contained HTML, no external assets)
- `GET /api/state` — the current state JSON
- `GET /api/report` — the current Markdown report
- `POST /api/stop` — request a graceful stop
- `WS /ws` — live event stream + confirmation bridge

## Safety notes

- The default bind is `127.0.0.1`. Running `--host 0.0.0.0` exposes the
  confirm/stop endpoints unauthenticated — breachload warns you at start.
  Don't do that on a shared network.
- The dashboard shows exactly the state the engine holds — it cannot make
  the engine do something the safety layer would reject.
