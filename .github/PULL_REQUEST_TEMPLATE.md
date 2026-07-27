## Summary

<!-- What does this change and why? -->

## Type

- [ ] feat  - [ ] fix  - [ ] docs  - [ ] refactor  - [ ] test  - [ ] chore

## Checklist

- [ ] `CHANGELOG.md` updated under `[Unreleased]`
- [ ] `ruff check .` passes
- [ ] `pytest` passes
- [ ] No engagement/target data, credentials, or secrets included

## Architecture compliance

- [ ] The LLM is not used to parse raw tool output (parsing stays in code)
- [ ] Any target-facing action still routes through `Validator.check`
- [ ] New adapters declare an honest `risk` class and are registered
- [ ] Safety-layer changes include tests
