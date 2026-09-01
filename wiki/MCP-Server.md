# MCP Server

`breachload mcp` turns breachload into a **security co-processor** for any
LLM agent. It speaks the Model Context Protocol over stdio (newline-delimited
JSON-RPC 2.0), so Claude Code, Claude Desktop, or a custom agent can call
breachload's reviewed pieces during a conversation.

## Why

An agent is good at *deciding* and *reading*. You don't want it inventing the
exact `certipy` flags, mis-identifying a hash format, or hand-rolling a shell
command that slips past your scope. breachload already owns those pieces as
**deterministic, tested code behind a hard safety layer**. The MCP surface
exposes exactly that layer — nothing that fires at a target, nothing that
bypasses scope/validator.

## The 14 tools

| Group | Tools | Use case |
|-------|-------|----------|
| Lookup | `fingerprint_to_cve`, `identify_hash`, `gtfobins`, `explain_term`, `parse_nmap_xml`, `parse_roast` | "What CVE is this fingerprint?" "What's the hashcat mode?" |
| Planning | `ad_killchain`, `pivot_plan`, `next_step`, `suggest`, `default_creds` | "What order should I attack these AD findings?" "What tunnel goes to that subnet?" |
| Detection | `secret_scan`, `privesc_classes` | "Grep this loot for secrets." "What class detectors hit this enum blob?" |
| Reporting | `render_report` | "Render this state as MD/HTML." |

## Install into Claude Code (1 line)

```bash
claude mcp add breachload -- breachload mcp
```

Or a manual MCP client config:

```json
{
  "mcpServers": {
    "breachload": { "command": "breachload", "args": ["mcp"] }
  }
}
```

Restart the client. Tools appear as `mcp__breachload__fingerprint_to_cve` etc.

## Try it without any client

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"fingerprint_to_cve","arguments":{"fingerprint":"webapp: Apache NiFi 1.21.0"}}}' \
  | breachload mcp
```

You'll get the version handshake and then a JSON body with the NiFi CVE lead
plus the ready exploit recipe.

## What it will NOT do

- Never runs a tool against a target. To fire, use the CLI where scope +
  validator + confirm-gates apply.
- Never bypasses the scope allowlist or the argv/no-shell validator.

If an agent asks breachload to plan an attack, it gets a plan. Firing that
plan is still an operator decision.

## Common workflows

1. **Working in Claude Code on a real box.** The agent hits `fingerprint_to_cve`
   whenever it sees a new stack; on AD, it hits `ad_killchain` on the current
   findings. You get reviewed leads instead of hallucinations.
2. **Blue-team / DFIR.** An agent reading a log dump uses `secret_scan` to
   surface every AWS key / JWT / DB URI, then `parse_roast` on any impacket
   output it finds.
3. **Report generation.** Hand a serialized state to `render_report` for a
   Markdown or HTML deliverable in one call.

See [docs/MCP.md](../docs/MCP.md) for the wire-level protocol walk-through.
