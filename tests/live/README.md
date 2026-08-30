# Live integration tests

These exercise breachload's **auto-foothold modules against real vulnerable
containers**, proving the exploit chains land in the wild — the guarantee the
mocked unit tests cannot give.

They are **opt-in and isolated**: a normal `pytest` run (and CI) skips them
entirely, so nothing here depends on Docker or the network unless you ask for it.

## Run

```bash
# 1. Bring up the deliberately-vulnerable targets (bound to 127.0.0.1 only)
docker compose -f tests/live/docker-compose.yml up -d

# 2. Wait for them to become healthy — Metabase takes ~40s on first boot
docker compose -f tests/live/docker-compose.yml ps

# 3. Run the live tests
BREACHLOAD_LIVE=1 pytest tests/live -m live -v

# 4. Tear down
docker compose -f tests/live/docker-compose.yml down
```

If `BREACHLOAD_LIVE` is unset, or a target port is not answering, each test
**skips** (it never fails for infrastructure reasons).

## Safety

The compose file binds every port to `127.0.0.1` only. These images are
intentionally exploitable — **never** expose them on a routable interface, and
tear them down when finished.

## Targets

| Service   | Image                       | CVE            | Module                 |
|-----------|-----------------------------|----------------|------------------------|
| Metabase  | `metabase/metabase:v0.46.6` | CVE-2023-38646 | `MetabaseFoothold`     |
| GLPI      | `diouxx/glpi:10.0.2`        | CVE-2022-35914 | `GlpiHtmlawedFoothold` |

Add a new row + a compose service + a test when you add a foothold module, so
every module has a live proof.
