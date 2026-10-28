The File guard checks every file Claude writes or edits, at the moment it writes it. It denies writes to secrets files and new content that contains a hardcoded credential, and it asks a human before Claude changes infrastructure-as-code, security-critical code or the guardrails themselves.

## At a glance

| | |
|---|---|
| **Runs on** | `PreToolUse` for `Write`, `Edit`, `MultiEdit` and `NotebookEdit` (15 s timeout) |
| **Decides** | ⛔ Deny, ✋ Ask, or no output (✅ the normal permission rules apply) |
| **Checks** | The target path, and the **new** content only (`content`, `new_string`, `new_source`, every `edits[].new_string`) |
| **Fails** | **Closed**: a crash or broken install answers ✋ Ask |
| **Audit** | One metadata-only line per deny or ask in `.claude/audit/guardrail-events.jsonl` |
| **Source** | [`.claude/hooks/file_guard.py`](https://github.com/pixelofsoftware/AI-Mods/blob/main/.claude/hooks/file_guard.py), path patterns in [`.claude/hooks/guard_common.py`](https://github.com/pixelofsoftware/AI-Mods/blob/main/.claude/hooks/guard_common.py) |

Legend: ⛔ Deny/Block · ✋ Ask · ⚠️ Warn · ✅ Allow

Ask matters here because it holds in every permission mode. In accept-edits or auto mode, Claude would otherwise apply these edits without anyone looking.

## How it decides

The hook takes `file_path` (or `notebook_path`), resolves it, and makes it relative to the repository root. A path outside the repository stays absolute. Then it runs these checks in order and stops at the first deny:

| Step | Check | Rule name in the audit log | Decision |
|---|---|---|---|
| 1 | Path is a secrets file | `secret_file_write` | ⛔ Deny |
| 2 | New content is over 500,000 characters | `oversized_content` | ✋ Ask |
| 3 | New content holds a `CRITICAL` credential | the detector name, e.g. `anthropic_api_key` | ⛔ Deny |
| 4 | New content holds any other `HIGH`+ finding | the detector names | ✋ Ask |
| 4 | Path is a guardrail file | `guardrail_change` | ✋ Ask |
| 4 | Path is infrastructure-as-code | `iac_change` | ✋ Ask |
| 4 | Otherwise, path is security-critical code | `security_critical_change` | ✋ Ask |

All step 4 reasons that apply are combined into **one** ask, separated by `; `. `MEDIUM` findings (emails, phone numbers) are ignored. Nothing in the old text (`old_string`) is checked.

## Rules

### `secret_file_write`

⛔ **Deny.** The path matches `SECRET_PATH_RE`, the same secret-path list the [Bash guard](Guardrail-Bash-Guard#secret_file_access) and [Read guard](Guardrail-Read-Guard) use: `.env` and its variants (the `.example`, `.sample`, `.template`, `.dist` and `.defaults` templates are allowed), `.envrc`, key and keystore files, credential directories such as `~/.ssh` and `~/.aws`, `*.tfstate`, anything under `secret/` or `secrets/`, `credentials.json` and similar.

```text
[AI guardrail] `.env.local` is a secrets file. The AI agent may not create or edit it; update the matching `.example` template and let a human fill real values.
[AI guardrail] `/home/user/.ssh/config` is a secrets file. The AI agent may not create or edit it; update the matching `.example` template and let a human fill real values.
[AI guardrail] `secrets/app.yaml` is a secrets file. …
```

Writing `.env.example` is allowed.

**Why.** Real secrets files hold real values. Claude shouldn't create them, and shouldn't see the values it would need to edit them.

**False positive?** Edit the `.example` template and fill real values yourself. A file under a `secrets/` directory that holds no secrets is still denied; rename the directory, or edit the file yourself.

### Hardcoded credential

⛔ **Deny.** The new content contains a finding that is in a credential category **and** `CRITICAL` severity: private key blocks; Anthropic, OpenAI, AWS, GCP, Azure storage, GitHub, GitLab, Slack and Stripe live keys; Slack webhooks; bearer tokens; passwords embedded in URLs. The audit log names the detector (for example `anthropic_api_key`). The detectors are on the [Detectors reference](Detectors-Reference) page.

Real output when Claude writes a fake Anthropic key (`sk-ant-api03-…`, built at runtime) into an `API_KEY` constant in `src/client.py`:

```text
[AI guardrail] hardcoded credential detected (API_KEY) in `src/client.py`. Read it from an environment variable or the secret manager instead, and rotate the value if it is real.
```

The same happens through `MultiEdit` edits and `NotebookEdit` cell sources. Known documentation values (such as AWS's `AKIA…EXAMPLE` key) and placeholders (`${VAR}`, `<your-key>`, `os.environ[...]`) don't match, so code that reads a key from the environment is fine.

**Why.** A credential written to a file ends up in git history, where it's hard to remove.

**False positive?** For test fixtures, build credential-shaped strings at runtime from pieces (see `tests/conftest.py`) so no literal key sits in the source. Never paste a real key to "test" the hook.

### Likely secret or regulated personal data

✋ **Ask.** The new content contains any `HIGH` or `CRITICAL` finding that wasn't denied above: JWTs (`AUTH_TOKEN`), `password=` / `api_key:` style assignments (`PASSWORD`), SSNs, card numbers, IBANs and medical record IDs (`PHI`).

```text
[AI guardrail] `tests/fixtures/user.json`: content contains likely secrets or regulated personal data (SSN); use obviously synthetic fixtures
[AI guardrail] `src/cfg.py`: content contains likely secrets or regulated personal data (PASSWORD); use obviously synthetic fixtures
[AI guardrail] `src/tok.py`: content contains likely secrets or regulated personal data (AUTH_TOKEN); use obviously synthetic fixtures
```

`password = os.environ["DB_PASSWORD"]` doesn't trigger: the detector ignores code references and placeholders.

**Why.** Fixtures copied from production are a common way real personal data ends up in a repository.

**False positive?** Approve it if the data is clearly synthetic. Better, use values the detectors skip: published test card numbers, an SSN with an invalid area such as `000`, or values assembled at runtime. The medical-record detector also matches ordinary words after *MRN* or *patient id* (see [Detectors reference](Detectors-Reference#medical_record_number)).

### `guardrail_change`

✋ **Ask.** The path matches `GUARDRAIL_PATH_RE`:

| Path | Notes |
|---|---|
| `.claude/` (anything under it) | Settings, hooks, local settings |
| `.mcp.json`, `CLAUDE.md` | |
| `scripts/claude_safeguard.py`, `scripts/precommit/`, `scripts/setup_guardrails.sh` | |
| `.pre-commit-config.yaml`, `.gitleaks.toml` | |
| `CODEOWNERS`, `.github/CODEOWNERS`, `.github/workflows/` | CI workflows land here |
| `config/claude-guardrails-policy.json`, `enterprise/` | |
| `docs/claude-guardrails.md`, `docs/claude-guardrails-setup.md` | |
| `pyproject.toml`, `.gitignore` | |

```text
[AI guardrail] `.claude/hooks/x.py`: this file is part of the AI guardrails; changes need security review (CODEOWNERS)
[AI guardrail] `.github/workflows/ci.yml`: this file is part of the AI guardrails; changes need security review (CODEOWNERS)
```

**Why.** An agent that can quietly loosen its own guardrails has no guardrails. These paths are also in [CODEOWNERS](Guardrail-Commit-and-Merge-Gates#codeowners).

**False positive?** Approve it if you asked for the change, and call out anything that loosens a control in the pull request. See [Changing the guardrails](Use-Case-Changing-the-Guardrails).

### `iac_change`

✋ **Ask.** The path matches `IAC_PATH_RE`:

- `*.tf`, `*.tfvars`, `*.hcl`, `*.bicep`
- `Dockerfile`, `Containerfile`, and variants such as `Dockerfile.dev`
- `compose.yml`, `docker-compose.yml` and their `.yaml` and suffixed forms
- `.yml`, `.yaml`, `.json`, `.j2`, `.ts` or `.py` files under a directory named `k8s`, `kubernetes`, `manifests`, `helm`, `charts`, `kustomize`, `deploy`, `deployment`, `infra`, `terraform`, `ansible`, `cloudformation` or `cdk`
- `serverless.yml`, `skaffold.yml`, `template.yml` (and `.yaml`)
- `*.template.json`, `*.template.yml`, `*.template.yaml`

```text
[AI guardrail] `infra/main.tf`: infrastructure-as-code: AI-generated changes require human review before merge (HITL)
[AI guardrail] `Dockerfile`: infrastructure-as-code: AI-generated changes require human review before merge (HITL)
[AI guardrail] `deploy/app.yaml`: infrastructure-as-code: AI-generated changes require human review before merge (HITL)
```

**Why.** Infrastructure changes have a large blast radius, and plausible-looking IaC can open a security group or drop encryption. See [Infrastructure and security code](Use-Case-Infrastructure-and-Security-Code).

**Limits.** CI files for systems other than GitHub Actions (for example `.gitlab-ci.yml` or `Jenkinsfile`) aren't in either list. `.github/workflows/` is covered by `guardrail_change`.

### `security_critical_change`

✋ **Ask**, when the path isn't already IaC. The path matches `SECURITY_CRITICAL_PATH_RE`: a directory or file whose name is `auth…`, `oauth…`, `sso`, `saml`, `security`, `crypto…`, `iam`, `rbac`, `acl`, `permission`/`permissions`, `secret`/`secrets` or `key`/`keys`, followed by `/`, a file extension, or `_`. Matching is case-insensitive.

| Path | Result |
|---|---|
| `src/auth/login.py`, `src/auth_utils.py`, `src/oauth2/client.py` | ✋ Ask |
| `lib/crypto_utils.py`, `app/iam.py`, `src/sso.py`, `src/rbac/x.go` | ✋ Ask |
| `src/permissions.py`, `src/keys.py` | ✋ Ask |
| `src/keyboard.py`, `src/keystore.go` | ✅ |

```text
[AI guardrail] `src/auth/login.py`: security-critical code (auth/crypto/access control): human review required (HITL)
```

**Why.** Authentication, cryptography and access-control bugs are security bugs. A human reviews them.

**False positive?** `auth…` matches any name starting with "auth", so `src/author.py` and `authors/` ask too. Approve the prompt; the cost is one click.

### `oversized_content`

✋ **Ask.** The new content is over 500,000 characters (`MAX_SCAN_CHARS`), so it isn't scanned.

```text
[AI guardrail] `big.txt`: content too large to scan for secrets (500001 chars); review before approving
```

**Why.** Scanning a huge payload could push the hook past its timeout, and a timed-out hook doesn't block. Asking is the safe answer.

## Several reasons at once

When more than one ask applies, you get one prompt that lists them all, for example a guardrail file that also contains a JWT:

```text
[AI guardrail] `<path>`: content contains likely secrets or regulated personal data (AUTH_TOKEN); this file is part of the AI guardrails; changes need security review (CODEOWNERS)
```

## What the File guard doesn't cover

- **Shell writes.** `echo … > infra/main.tf` or `cp new.py src/auth/login.py` run through the Bash tool, which this hook doesn't see. The [Bash guard](Guardrail-Bash-Guard#guardrail_change) asks for shell writes to guardrail files and denies writes to secrets files, but not for IaC or security-critical paths. Those are caught at merge time by [CODEOWNERS](Guardrail-Commit-and-Merge-Gates#codeowners) and the reviewers.
- **Pattern limits.** Free-text personal data and unknown credential formats aren't detected. See [Detectors reference](Detectors-Reference).
- **Old content.** Only the text being written is scanned, not what's already in the file.

See [Limitations and threat model](Limitations-and-Threat-Model).

## When the hook itself fails

| Failure | Decision and reason |
|---|---|
| `guard_common` can't be imported | ✋ `[AI guardrail] file_guard could not load its rules (<ErrorType>); manual review required` |
| Any error while running, such as malformed event JSON | ✋ `[AI guardrail] file_guard error (<ErrorType>); manual review required` |

## Audit records

Real record for an edit to `infra/main.tf` in accept-edits mode. The path is recorded; the content never is.

```json
{"@timestamp": "2026-10-28T06:19:39.579985+00:00", "decision": "ask", "event": "PreToolUse", "hook": "file_guard", "path": "infra/main.tf", "permission_mode": "acceptEdits", "rules": ["iac_change"], "session_id": "s-123", "tool": "Edit", "user": "dev"}
```

`secret_file_write` denies are recorded without a `path`. See [Audit logs](Audit-Logs).

## Relationship to the permission rules

`.claude/settings.json` also has `Edit(...)` ask rules for the same kinds of paths (`**/*.tf`, `**/auth/**`, `/.claude/**` and so on) and deny rules for a few secrets files. The hook's patterns are broader (any `.env` variant, any `auth…` name) and also cover `Write`, `MultiEdit` and `NotebookEdit`. See [Project settings](Settings-Project).

## Try it

```bash
echo '{"tool_name":"Edit","tool_input":{"file_path":"infra/main.tf","old_string":"a","new_string":"b"}}' \
  | CLAUDE_GUARDRAIL_AUDIT=0 python3 .claude/hooks/file_guard.py
```

## Related pages

- [Bash guard](Guardrail-Bash-Guard)
- [Read guard](Guardrail-Read-Guard)
- [Detectors reference](Detectors-Reference)
- [Infrastructure and security code](Use-Case-Infrastructure-and-Security-Code)
- [Changing the guardrails](Use-Case-Changing-the-Guardrails)
- [Limitations and threat model](Limitations-and-Threat-Model)
