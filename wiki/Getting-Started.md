# Getting Started

## Install

```bash
git clone https://github.com/Noxiidus/breachload
cd breachload
python -m venv .venv && source .venv/bin/activate
pip install -e .
```

## Configure an engagement

Copy the example and edit the scope. The scope is the **only** thing breachload
will touch.

```yaml
# engagements/my-lab.yaml
name: my-lab
mode: full-auto
targets:
  - 10.10.10.0/24
exclude:
  - 10.10.10.1
auto_threshold: active   # passive|recon|active|intrusive|exploit|destructive
```

## Run

```bash
# Optional — omit for the offline heuristic planner
export ANTHROPIC_API_KEY=sk-ant-...

breachload run engagements/my-lab.yaml --phase recon
breachload status engagements/my-lab.yaml
```

State, audit log, and any artifacts land in `engagements/<name>/` — which is
git-ignored. Never commit that directory.

## Online vs offline

- **Online** (API key set): Claude plans each step and explains its reasoning.
- **Offline** (no key): a heuristic planner drives recon end-to-end. Good for
  testing the pipeline and adapters without spending tokens.
