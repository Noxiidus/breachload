# Local-first (Ollama / LM Studio)

You can run breachload's LLM planner against a local model — Ollama, LM
Studio, `llama.cpp` server, vLLM, any OpenAI-compatible endpoint. Fully
offline decisions, no cloud API bill, no data leaving your machine.

## Setup

```bash
# Ollama (default port 11434)
ollama serve &
ollama pull llama3

export BREACHLOAD_LOCAL_LLM_URL=http://127.0.0.1:11434
export BREACHLOAD_LOCAL_LLM_MODEL=llama3
```

or:

```bash
# LM Studio (default OpenAI-compat on 1234/v1)
# start the local server in LM Studio, then:
export BREACHLOAD_LOCAL_LLM_URL=http://127.0.0.1:1234/v1
export BREACHLOAD_LOCAL_LLM_MODEL=<the model name you loaded>
```

That's the whole configuration.

## Verify

```bash
python -c "from breachload.core.llm import Planner; print('online:', Planner().online)"
# online: True
```

## Precedence

- `BREACHLOAD_LOCAL_LLM_URL` set → local backend wins.
- Not set, `ANTHROPIC_API_KEY` set → Claude.
- Neither set → the deterministic heuristic planner.

The local backend deliberately takes precedence over Claude so you can opt
into offline decisions with a single env var, without unsetting your key.

## What breachload calls

The Planner POSTs OpenAI-compatible chat completions:

```
POST /v1/chat/completions
{
  "model": "<BREACHLOAD_LOCAL_LLM_MODEL>",
  "messages": [
    {"role": "system", "content": "<SYSTEM_PROMPT>"},
    {"role": "user",   "content": "<serialized state + tools>"}
  ],
  "temperature": 0,
  "stream": false
}
```

If that path 404s (older Ollama without the OpenAI shim), it retries
`POST /api/chat` (the native Ollama endpoint).

Any failure — network, JSON parse, non-2xx — silently falls back to the
deterministic heuristic. The run never crashes because the model was slow
or unreachable.

## Model choice

- **`llama3` / `llama3.1` (8B-70B)** — decent JSON adherence out of the
  box, works for the planner shape.
- **`qwen2.5` / `mistral`** — also solid; pick by what your GPU fits.
- **Instruct-tuned only** — the base models won't respect the JSON schema.

The Planner expects a strict JSON response of the form:

```json
{"action":"run|phase_complete", "tool":"...", "target":"...",
 "args":{...}, "rationale":"..."}
```

If your local model returns Markdown code fences or preamble, the parser
extracts the first `{...}` and validates it — most modern instruct models
work fine.

## Why do this

- **Air-gapped engagements** — no cloud API allowed by the client.
- **Cost** — a 30-minute run on a real box is many API calls; local is free.
- **Privacy** — nothing about your target's fingerprint leaves your box.

## What you don't lose

The deterministic core is unchanged. Every safety-critical decision (scope,
argv validation, confirm-gates, tamper-evident audit) runs the same code
regardless of which backend picked the tool. The LLM is only ever a
suggester.
