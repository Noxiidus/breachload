# breachload MCP server

`breachload mcp` turns breachload into a **security co-processor for LLM agents**.
It speaks the [Model Context Protocol](https://modelcontextprotocol.io) over stdio
(newline-delimited JSON-RPC 2.0), so any MCP client — Claude Code, Claude Desktop,
or your own — can call breachload's deterministic, reviewed capabilities.

## Why

An LLM agent is good at *deciding* and *reading*, but you don't want it inventing
the exact `certipy` flags, mis-identifying a hash, or hand-rolling a shell command
that slips past your scope. breachload already owns those pieces as **deterministic,
tested code behind a hard safety layer**. The MCP server exposes exactly that layer
— and nothing that fires at a target.

```
                 ┌─────────────────────────┐
   drives  ───▶  │  LLM agent (Claude Code) │  reads results, decides next step
                 └───────────┬─────────────┘
                             │  JSON-RPC over stdio (MCP)
                             ▼
                 ┌─────────────────────────┐
                 │   breachload mcp server  │   pure, deterministic tools
                 │  fingerprint→CVE · adchain│
                 │  parse_roast · identify_hash
                 │  pivot_plan · gtfobins ...│
                 └─────────────────────────┘
                    (never fires at a target;
                     never bypasses scope/validator)
```

The division is the whole point: **the agent drives, breachload contributes the
trustworthy reviewed parts.** To actually *run* something against a target, the
agent still goes through the CLI, where scope, the validator, and confirm-gates
apply.

## Exposed tools

| Tool | What it returns |
|------|-----------------|
| `fingerprint_to_cve` | A web-app fingerprint (product/version/banner) → known-CVE leads + ready exploit commands |
| `ad_killchain` | AD finding titles (BloodHound/ADCS/roasting) → a ranked path to Domain Admin with the next command per step |
| `parse_roast` | impacket AS-REP/Kerberoast output → findings + crackable hashes |
| `identify_hash` | A hash → hashcat mode + crack commands |
| `pivot_plan` | Compromised edge host + subnet → sshuttle/chisel/ligolo/ssh tunnelling commands |
| `explain_term` | A security term (ssti, kerberoast, esc1, …) → a plain-language explanation |
| `gtfobins` | A SUID/sudo binary → GTFOBins escalation techniques |
| `parse_nmap_xml` | nmap XML → structured hosts/services/findings |

## Protocol walk-through

Start the server:

```bash
breachload mcp
```

Then it's a normal MCP handshake. Example (requests you send ▶, responses ◀):

```jsonc
▶ {"jsonrpc":"2.0","id":1,"method":"initialize"}
◀ {"jsonrpc":"2.0","id":1,"result":{
     "protocolVersion":"2024-11-05",
     "capabilities":{"tools":{}},
     "serverInfo":{"name":"breachload","version":"0.20.0"}}}

▶ {"jsonrpc":"2.0","id":2,"method":"tools/list"}
◀ {"jsonrpc":"2.0","id":2,"result":{"tools":[
     {"name":"fingerprint_to_cve","description":"...","inputSchema":{...}}, ... ]}}

▶ {"jsonrpc":"2.0","id":3,"method":"tools/call","params":{
     "name":"fingerprint_to_cve",
     "arguments":{"fingerprint":"webapp: Apache NiFi"}}}
◀ {"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":
     "[ { \"title\": \"Apache NiFi unauthenticated API -> RCE (CVE-2023-34468)\",
          \"cve\": [\"CVE-2023-34468\"], \"severity\": \"critical\",
          \"exploit\": \"curl -s http://{TARGET}:{PORT}/nifi-api/access/config ...\" } ]"}]}}
```

Try it from a shell without any client:

```bash
printf '%s\n%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"fingerprint_to_cve","arguments":{"fingerprint":"webapp: Apache NiFi"}}}' \
  | breachload mcp
```

## Wire it into Claude Code

Add breachload as an MCP server (stdio):

```bash
claude mcp add breachload -- breachload mcp
```

or in your MCP client config:

```json
{
  "mcpServers": {
    "breachload": { "command": "breachload", "args": ["mcp"] }
  }
}
```

Now the agent can call e.g. `fingerprint_to_cve` while you work, and get
breachload's reviewed lead instead of a hallucinated one.

## Safety notes

- The MCP surface is **read/plan only** — no tool touches a target, so there is no
  scope check to bypass (there is nothing to fire).
- Anything that runs against a target stays in the CLI, behind the scope allowlist,
  the argv/no-shell validator, and the confirm-gates.
- Handlers are pure functions over JSON (`breachload/mcp/server.py`), unit-tested
  without any socket — a broken tool reports an error as content, never crashes the
  server.
