# breachload wiki

Autonomous pentest copilot for Linux — guides an engagement from recon to report,
runs tools, parses their output into structured state, decides the next step, and
generates findings, while a deterministic safety layer keeps every action inside
the authorized scope.

> ⚠️ For **authorized** testing only — pentests you have permission for, CTF/labs,
> and research. See [[Safety-Model]].

## Pages

- **[[Getting-Started]]** — install and run your first engagement
- **[[Architecture]]** — how the pieces fit together
- **[[Safety-Model]]** — scope, risk classes, and what full-auto really does
- **[[Writing-Adapters]]** — the main extension point
- **[Roadmap](https://github.com/Noxiidus/breachload/blob/main/ROADMAP.md)** — versioned milestones

## The one rule

> The deterministic core owns the truth. The LLM only decides and explains.

Parsing, scope, and state are code. Claude decides the next action and explains
why — it never parses raw output and never bypasses the safety layer.
