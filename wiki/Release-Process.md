# Release Process

Every release MUST touch these five things — the last two are the ones that
were forgotten in v0.17-v0.19 and caused the "released version older than main"
gap.

## Checklist

1. **Bump `pyproject.toml`** version.
2. **Bump `breachload/__init__.py`** `__version__` to match.
3. **CHANGELOG**: add the `## [X.Y.Z] - YYYY-MM-DD` section under
   `## [Unreleased]`, with subsections `### Added / Fixed / Changed`.
4. **README**: update the "Latest release: **vX.Y.Z**" badge line + the test
   count if it moved.
5. **Gate** (mandatory): `ruff check breachload/ tests/ && mypy breachload/ &&
   pytest -q --no-cov` MUST be green before push.
6. **Commit + push**: `chore(release): vX.Y.Z`.
7. **Tag + GitHub release**:
   ```bash
   git tag -a vX.Y.Z HEAD -m "breachload vX.Y.Z - <short summary>"
   git push origin vX.Y.Z
   # extract the CHANGELOG section for this version, then:
   gh release create vX.Y.Z --title "vX.Y.Z - <short summary>" \
       --notes-file <notes-path> --latest
   ```
8. **CI must be green** on the release commit before you tell anyone.
9. **Memory update**: add a one-paragraph memory entry for the new release
   under `breachload-project.md`.

## The pre-push gate that stops CI-fail emails

```bash
# Run these three ALWAYS before `git push`:
ruff check breachload/ tests/       # 0 errors
python -m mypy breachload/          # 0 errors
python -m pytest -q --no-cov        # all green
```

If any step is red, fix it before pushing. Do not push "just to see if CI
passes" — the whole point of the gate is that the answer is already known.

## Why the README + CHANGELOG updates matter

- The README's "Latest release: vX.Y.Z" line is what a first-time visitor
  reads. A stale badge undersells the tool.
- The GitHub release page pulls from the CHANGELOG section — if there's no
  entry, the release notes are empty.
- Skipping tag+release makes `git tag` and `pip install` disagree with
  `pyproject.toml`, which is exactly what happened v0.17-v0.19 (fixed later
  by back-tagging).

## Versioning

SemVer. Concretely:
- **PATCH** (`v0.20.1`) — bug fix only, no new commands or capabilities.
- **MINOR** (`v0.21.0`) — new command(s), new class detector(s), new MCP tool(s).
- **MAJOR** (`v1.0.0`) — a change that breaks the ToolAdapter or MCP contract
  (do not do this without written intent).
