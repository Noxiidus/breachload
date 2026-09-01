# Reporting & audit

Three deliverables, one command, plus a tamper-evident audit trail.

## Generate the report

```bash
breachload report <cfg>            # Markdown by default (engagements/<name>/report.md)
breachload report <cfg> --html     # + self-contained HTML report
breachload report <cfg> --pdf      # + PDF (courier-only, no external deps)
breachload report <cfg> --html --pdf
```

## What's in the report

Every format carries the same sections:

- **Executive summary** — counts (hosts / services / findings by severity /
  credentials / artifacts / flags), plus a "confirmed vs suspected" split so
  the reader knows what's proven vs merely inferred.
- **Attack path** — a plain-language narrative synthesised from state (recon
  → foothold leads → creds → privesc leads → captured flags).
- **Hosts & services** table.
- **Findings** — ordered by severity. Each with:
  - `[CRITICAL/HIGH/…]` severity tag
  - **[CONFIRMED]** / **[suspected]** status badge + proof string
  - **CVSS** score (real number from the KB, or the qualitative band)
  - Location (host + port)
  - CVE list
  - Description + `Guided exploit` block (review-then-run) + Remediation
  - Evidence excerpt
  - **Reproduce** — the successful commands from `history` that targeted
    this host
- **Credentials** table.
- **Generated artifacts** table (payloads, PoCs).
- **Activity timeline** — every action, its exit code, and whether it was
  blocked/skipped.
- **Audit integrity** — verification of the hash chain (see below).

## HTML report

Fully self-contained (inline CSS, no external assets, no network), so you
can email it or drop it in a shared drive. Severity summary bar at the top,
colored badges per finding, dark mode friendly.

## Tamper-evident audit log

Every action, decision, and safety block writes a JSONL record to
`engagements/<name>/audit.jsonl`. Each record is **SHA-256-chained to the
previous one**:

```
{"ts":..., "event":"authorization", ..., "prev":"<prev-hash>", "hash":"<this>"}
```

Editing or deleting any past line breaks every subsequent hash. To verify:

```bash
breachload audit <cfg> --verify
# audit chain intact - 42 records, no tampering detected
```

If someone tampered mid-engagement:

```
audit chain BROKEN at line 27: line 27: content hash mismatch (record edited)
```

This is genuine integrity (detects tampering); it is not a signature — it
does not prove *who* wrote it.

The report's `Audit integrity` section pulls the same verification so a
reader sees the chain status without leaving the document.

## Where the files land

```
engagements/<name>/
  state.json          # the full typed state (source of truth)
  session.json        # the registered foothold, if any
  audit.jsonl         # every action, hash-chained
  report.md           # after breachload report
  report.html         # after --html
  report.pdf          # after --pdf
  artifacts/          # generated payloads/PoCs (git-ignored)
```

## Customization

- **CVSS on a new KB entry** — add `cvss: 9.8` to the `webapp_kb.json`
  entry; the report picks it up automatically.
- **Suppress a finding** — remove it from `state.json` and re-run report
  (state is the source of truth; the report is derived).
- **Shorten the timeline** — the timeline is the raw history. If you want a
  redacted engagement report, hand-edit the timeline section after generation
  (the Markdown is the machine-diffable record; edits stay yours).
