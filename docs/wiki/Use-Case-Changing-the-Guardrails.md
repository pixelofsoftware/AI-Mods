This page is for contributors and security engineers who want to change a control: add a detector, tighten a rule, allow a new domain, or relax something that gets in the way. It shows which files hold each control, how the policy baseline and drift check work, which tests to add, and how review works, with one tightening and one loosening example.

> **Placeholders on this page:** *AppSec* is the template's name for the team that owns the guardrails. In this repository the code owner is `@pixelofsoftware`.

## Where each control lives

| Control | File(s) | Notes |
|---|---|---|
| Allow, ask and deny rules; sandbox; hook wiring; MCP enablement | [`.claude/settings.json`](https://github.com/pixelofsoftware/AI-Mods/blob/main/.claude/settings.json) | Checked against the policy baseline |
| MCP servers | [`.mcp.json`](https://github.com/pixelofsoftware/AI-Mods/blob/main/.mcp.json) | Checked against the policy baseline |
| The baseline itself | [`config/claude-guardrails-policy.json`](https://github.com/pixelofsoftware/AI-Mods/blob/main/config/claude-guardrails-policy.json) | See [Policy baseline](Settings-Policy-Baseline) |
| Secret, guardrail, IaC and security-critical **path patterns** | [`.claude/hooks/guard_common.py`](https://github.com/pixelofsoftware/AI-Mods/blob/main/.claude/hooks/guard_common.py) (`SECRET_PATH_RE`, `GUARDRAIL_PATH_RE`, `IAC_PATH_RE`, `SECURITY_CRITICAL_PATH_RE`) | The hooks don't read path lists from the policy file (that's on the roadmap) |
| Shell rules | [`.claude/hooks/bash_guard.py`](https://github.com/pixelofsoftware/AI-Mods/blob/main/.claude/hooks/bash_guard.py) | `NETWORK_EGRESS`, `SECRET_STORES`, `PUBLISH` and `check_segment()` |
| Prompt, file and read decisions | `prompt_guard.py`, `file_guard.py`, `read_guard.py` | |
| Credential and personal-data **detectors**; API output rules | [`scripts/claude_safeguard.py`](https://github.com/pixelofsoftware/AI-Mods/blob/main/scripts/claude_safeguard.py) (`DEFAULT_RULES`, `DEFAULT_OUTPUT_RULES`) | Shared by the hooks, pre-commit and the API middleware |
| Commit-time checks | [`.pre-commit-config.yaml`](https://github.com/pixelofsoftware/AI-Mods/blob/main/.pre-commit-config.yaml), [`scripts/precommit/check_ai_guardrails.py`](https://github.com/pixelofsoftware/AI-Mods/blob/main/scripts/precommit/check_ai_guardrails.py) | |
| Organisation policy | [`enterprise/managed-settings.json`](https://github.com/pixelofsoftware/AI-Mods/blob/main/enterprise/managed-settings.json) | Deployed by admins; a repo change does nothing until it's redeployed |
| Who must review | [`.github/CODEOWNERS`](https://github.com/pixelofsoftware/AI-Mods/blob/main/.github/CODEOWNERS) | |
| What Claude is told | [`CLAUDE.md`](https://github.com/pixelofsoftware/AI-Mods/blob/main/CLAUDE.md) | |
| The written rules | [`docs/claude-guardrails.md`](https://github.com/pixelofsoftware/AI-Mods/blob/main/docs/claude-guardrails.md), [`docs/claude-guardrails-setup.md`](https://github.com/pixelofsoftware/AI-Mods/blob/main/docs/claude-guardrails-setup.md) | |

All of these are guardrail files: CODEOWNERS covers them, and `file_guard` asks before Claude edits any of them, including shell writes such as `echo … > .claude/settings.json` or `sed -i`:

```text
[AI guardrail] `.claude/settings.json`: this file is part of the AI guardrails; changes need security review (CODEOWNERS)
```

```text
[AI guardrail] shell write to AI guardrail file `.claude/settings.json` needs security review
```

`CLAUDE.md` also tells Claude not to edit these files unless you explicitly ask, and to call out anything that loosens a control.

## The baseline and the drift check

`validate-claude-config` runs on every commit, every push and in CI. It compares `.claude/settings.json` and `.mcp.json` with the policy file and fails if:

- a `required_settings` value differs (bypass lock, sandbox on, no unsandboxed fallback, no auto-allow, empty `excludedCommands`, `enableAllProjectMcpServers: false`);
- the default mode is `bypassPermissions`, `auto` or `acceptEdits`;
- a `required_deny_rules` or `required_ask_rules` entry is missing;
- an allow rule matches a `forbidden_allow_rule_patterns` entry, or allows an MCP server that isn't enabled;
- a required hook is missing, a matcher doesn't cover its tools, or a hook runs anything other than the approved scripts with the exact `python3 "${CLAUDE_PROJECT_DIR}/.claude/hooks/<name>.py"` command;
- a `forbidden_settings_keys` key is present (`apiKeyHelper`, `awsAuthRefresh`, `awsCredentialExport`, `otelHeadersHelper`, `statusLine`, `disableAllHooks`);
- an `env` name matches `forbidden_env_patterns` (`ANTHROPIC_*`, `*_BASE_URL`, `CLAUDE_CODE_USE_*`, proxies, `NODE_OPTIONS`, `NODE_TLS_REJECT_UNAUTHORIZED`, `CLAUDE_GUARDRAIL_AUDIT`);
- a sandbox domain isn't in `allowed_sandbox_domains`;
- an MCP server URL isn't approved, a header holds a literal credential, a stdio server isn't an approved command, or `.mcp.json` and `enabledMcpjsonServers` disagree.

Run it yourself:

```bash
python3 scripts/precommit/check_ai_guardrails.py validate-config
```

Exit codes: `0` ok, `1` drift, `2` the config couldn't be read.

The rule of thumb: **if the change touches `.claude/settings.json` or `.mcp.json` in a way the baseline cares about, update the policy file in the same commit.** That puts the loosening in front of the reviewer in a file they own.

Path patterns and detectors aren't in the baseline. They're kept consistent by tests instead (next section).

## Tests to add

Every guard change needs a test that fails before the change and passes after it. Where to put it:

| Change | Test file | Pattern |
|---|---|---|
| A bash, file, read or prompt rule | [`tests/test_hooks.py`](https://github.com/pixelofsoftware/AI-Mods/blob/main/tests/test_hooks.py) | Use the `hook` fixture: it runs the script with JSON on stdin, like Claude Code does |
| A detector or an output rule | [`tests/test_safeguard.py`](https://github.com/pixelofsoftware/AI-Mods/blob/main/tests/test_safeguard.py) | Positive cases and false-positive cases |
| Settings, policy or pre-commit config | [`tests/test_config.py`](https://github.com/pixelofsoftware/AI-Mods/blob/main/tests/test_config.py) | Copy the config to a temp dir, mutate it, expect `validate-config` to fail |
| A secret or guardrail path | [`tests/test_review2_regressions.py`](https://github.com/pixelofsoftware/AI-Mods/blob/main/tests/test_review2_regressions.py) | Add the path to `SECRET_SAMPLES` or `GUARDRAIL_SAMPLES` |

The drift tests in `test_review2_regressions.py` check that:

- every **guardrail path** matches `GUARDRAIL_PATH_RE`, is covered by CODEOWNERS, triggers ✋ in `file_guard`, and is listed in `CLAUDE.md`;
- every **secret path** is denied by the hooks, blocked by `forbid-ai-artifacts`, and gitignored;
- every **template** (`.env.example` and friends, `*.pub`) is allowed everywhere.

So a new guardrail file means editing `GUARDRAIL_PATH_RE`, CODEOWNERS and `CLAUDE.md` (and usually an `Edit(...)` ask rule in settings) together. A new secret path means `SECRET_PATH_RE`, `forbidden_paths` in the policy file and `.gitignore` together.

**Build credential-shaped strings at runtime.** The repository's own scanners (and `file_guard`, if you use Claude) reject literal fake keys. Follow [`tests/conftest.py`](https://github.com/pixelofsoftware/AI-Mods/blob/main/tests/conftest.py):

```python
anthropic_key = "sk-ant-" + "api03-" + "Zq9xLm2Pw7" * 5
```

**Keep the hooks stdlib-only and the regexes bounded** (`{20,512}`, not `+`), and make new code fail closed: when unsure, ask; never allow. See [CONTRIBUTING.md](https://github.com/pixelofsoftware/AI-Mods/blob/main/CONTRIBUTING.md).

## The process, step by step

1. **Discuss first** for anything that loosens a control: an issue, or a message to AppSec.
2. **Branch.** The `no-commit-to-branch` hook stops commits to `main` and `master`.
3. **Make the change**, plus the policy file if needed, plus the test. Approve each ✋ prompt if you're using Claude.
4. **Run what CI runs:**

   ```bash
   python3 -m pytest
   pre-commit run --all-files
   scripts/setup_guardrails.sh --check
   ```

5. **Update the docs and [CHANGELOG.md](https://github.com/pixelofsoftware/AI-Mods/blob/main/CHANGELOG.md)** if behaviour changed.
6. **Open the pull request** and fill in the template. Its "Effect on the guardrails" section has three boxes; tick exactly one:

   ```markdown
   - [ ] No guard behaviour changes (docs, tests, refactoring)
   - [ ] Makes a guard **stricter** (new detector, new deny or ask rule)
   - [ ] **Loosens** a guard (removes or relaxes a rule): explain why below
   ```

   If it loosens a control, say what it allows now and why that's safe. The checklist below it asks for the test, both check runs, synthetic test data, the policy file and the docs.
7. **Code-owner review.** CODEOWNERS requests it automatically; branch protection makes it required.
8. **CI** runs the `guardrails` job: the test suite and every pre-commit check.
9. **Roll out.** Project changes apply when developers pull. Changes to `enterprise/managed-settings.json` apply only after admins redeploy them ([Organisation rollout](Use-Case-Organisation-Rollout)).

## Example 1: a tightening change

**Problem.** The bash guard denies `gradle publish` and `mvn deploy`, but it matches the program name, so the wrapper scripts get through:

| Command | Today |
|---|---|
| `gradle publish` | ⛔ `` `gradle publish` publishes artifacts (supply-chain risk); release through CI `` |
| `./gradlew publish` | No decision from the guard |
| `./mvnw deploy` | No decision from the guard |

**1. A quick fix in settings.** Add deny rules. Tightening needs no policy-file change, because the baseline only lists the rules that must be present:

```diff
     "deny": [
       …
+      "Bash(./gradlew publish)",
+      "Bash(./gradlew publish *)",
+      "Bash(./mvnw deploy)",
+      "Bash(./mvnw deploy *)",
```

Optionally add them to `required_deny_rules` too, so nobody can remove them later without review.

**2. The robust fix in the hook**, so `bash -c './gradlew publish'` and other wrappers are caught as well. A sketch for `check_segment()` in `bash_guard.py`:

```python
WRAPPER_SCRIPTS = {"gradlew": "gradle", "mvnw": "mvn"}

publish_argv = [WRAPPER_SCRIPTS.get(cmd, argv[0])] + argv[1:]
for prefix in PUBLISH:
    if _invokes(publish_argv, prefix):
        v.add("deny", "package_publish", f"`{' '.join(prefix)}` publishes artifacts (supply-chain risk); release through CI")
```

**3. The test**, in `tests/test_hooks.py`. It fails today and passes after the fix:

```python
@pytest.mark.parametrize("command", ["./gradlew publish", "./mvnw deploy", "bash -c './gradlew publish'"])
def test_build_wrapper_publish_is_denied(hook, command):
    out = hook("bash_guard.py", {"tool_name": "Bash", "tool_input": {"command": command}})
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
```

**4. The pull request.** Tick "Makes a guard **stricter**". Add a CHANGELOG line under *Unreleased*.

## Example 2: a loosening change

**Request.** A Java team wants Maven Central reachable from the sandbox, so `./gradlew test` can resolve dependencies.

**1. Change the setting.** Add the domain to `sandbox.network.allowedDomains` in `.claude/settings.json`. Commit it alone, and the drift check fails:

```text
AI guardrail configuration drift detected:
  - .claude/settings.json: sandbox domain `repo.maven.apache.org` is not in allowed_sandbox_domains

If the change is intentional, update config/claude-guardrails-policy.json in the same PR so security review sees it.
```

**2. Update the baseline** in the same commit:

```diff
   "allowed_sandbox_domains": [
     "github.com",
     …
-    "artifacts.internal.example.com"
+    "artifacts.internal.example.com",
+    "repo.maven.apache.org"
   ],
```

**3. Update the managed settings** too, if your organisation deploys them: with `allowManagedDomainsOnly: true`, only the managed domain list counts. Admins redeploy afterwards.

**4. Consider a test.** A config test can assert that the domain is present, so it's not dropped by accident. For a pure allowlist change, the drift check is often enough.

**5. The pull request.** Tick "**Loosens** a guard" and explain:

- what it allows: sandboxed commands may now reach `repo.maven.apache.org`;
- why that's safe: it's a read-only public package registry, like the PyPI and npm hosts already listed;
- the alternative considered: routing through the internal artifact proxy, which avoids widening the list.

Reviewers push back hardest on loosening changes that remove a **required** rule (for example `Bash(curl *)` or `Bash(git push *)`), add a forbidden allow pattern, or add `excludedCommands`. Those need a strong reason, an owner, and usually an expiry; see [False positives and exceptions](Use-Case-False-Positives-and-Exceptions#step-5-ask-for-an-exception-when-you-need-something-the-policy-forbids).

## Related pages

- [Policy baseline](Settings-Policy-Baseline)
- [Project settings](Settings-Project)
- [Commit and merge gates](Guardrail-Commit-and-Merge-Gates)
- [Detectors reference](Detectors-Reference)
- [False positives and exceptions](Use-Case-False-Positives-and-Exceptions)
- [Architecture](Architecture)
