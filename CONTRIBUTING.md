# Contributing to Claude Guardrails

Thanks for helping make AI-assisted development safer. Contributions of every size are welcome. The most valuable ones are:

- **Bypasses** of a guard. Report these privately; see [SECURITY.md](SECURITY.md).
- **False positives** that slow down legitimate work: [open an issue](https://github.com/pixelofsoftware/AI-Mods/issues/new/choose).
- **New detectors** for credential or personal-data formats.
- **Docs** that make setup easier for your platform or stack.

## Set up a development environment

```bash
git clone https://github.com/pixelofsoftware/AI-Mods.git
cd AI-Mods
python3 -m pip install pytest pyyaml pre-commit
scripts/setup_guardrails.sh        # installs the git hooks and self-tests every guard
```

Before you open a pull request, run what CI runs:

```bash
python3 -m pytest                  # the test suite
pre-commit run --all-files         # secret scanning, SAST, config drift checks
```

## Guidelines

- **Add a test that fails before your change and passes after it.** Every guard fix in this repository has a regression test, so please keep it that way.
- **Use synthetic data only.** Build credential-shaped test strings at runtime (for example `"sk-ant-" + "api03-" + ...`, see `tests/conftest.py`) so the repository's own secret scanners stay quiet. Never commit a real secret, even an expired one.
- **Keep the hooks dependency-free.** Everything under `.claude/hooks/` must run on the Python 3.9+ standard library alone.
- **Keep regexes bounded.** Use bounded quantifiers (`{20,512}`, not `+`) and anchors, so a hostile input can't cause catastrophic backtracking.
- **Fail closed.** When a guard can't decide (unparseable input, an internal error), it should ask, never allow.
- **Changing a guardrail?** Update [`config/claude-guardrails-policy.json`](config/claude-guardrails-policy.json) in the same pull request, and explain in the description why the control changes and whether it loosens anything. The `validate-claude-config` check fails otherwise.
- **Keep the lists in sync.** Paths that count as secrets or guardrails appear in several places (hooks, settings, CODEOWNERS, `.gitignore`, the policy file). The drift tests in `tests/test_review2_regressions.py` tell you if you missed one.

## Pull requests

1. Fork the repository and create a branch from `main`.
2. Make your change, with tests.
3. Run `python3 -m pytest` and `pre-commit run --all-files`.
4. Open a pull request and fill in the template.

CI runs the `guardrails` job on every pull request. Changes to the guardrails themselves, CI or infrastructure files need code-owner review.

## Using Claude Code on this repository

This repository runs its own guardrails, so Claude Code is subject to them here too. That's intentional. If a guard blocks something you think it shouldn't, that's a false-positive report waiting to happen.

## License

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE).
