## What this changes

<!-- What does this pull request do, and why? Link the issue if there is one. -->

## Effect on the guardrails

- [ ] No guard behaviour changes (docs, tests, refactoring)
- [ ] Makes a guard **stricter** (new detector, new deny or ask rule)
- [ ] **Loosens** a guard (removes or relaxes a rule): explain why below

<!-- If this loosens a control, say what it allows now and why that's safe. -->

## Checklist

- [ ] Added a test that fails before this change and passes after it
- [ ] `python3 -m pytest` passes
- [ ] `pre-commit run --all-files` passes
- [ ] Test data is synthetic; no real secrets or personal data
- [ ] Updated `config/claude-guardrails-policy.json` if guardrail settings changed
- [ ] Updated the docs and `CHANGELOG.md` if behaviour changed
