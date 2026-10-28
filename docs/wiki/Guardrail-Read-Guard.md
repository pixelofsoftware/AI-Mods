The Read guard stops Claude's file-reading tools from opening secrets files. It applies one secret-path pattern to every path and glob the tools are given, so variants that a name-by-name deny list would miss (`.env.prod`, `.envrc`, `kubeconfig-staging`) are denied too.

## At a glance

| | |
|---|---|
| **Runs on** | `PreToolUse` for `Read`, `Grep`, `Glob` and `NotebookRead` (15 s timeout) |
| **Decides** | ⛔ Deny, or no output (✅ the normal permission rules apply) |
| **Rule** | `secret_file_read` |
| **Fails** | **Closed**: a crash or broken install answers ✋ Ask |
| **Audit** | One line per deny, with the file's base name |
| **Source** | [`.claude/hooks/read_guard.py`](https://github.com/pixelofsoftware/AI-Mods/blob/main/.claude/hooks/read_guard.py), patterns in [`.claude/hooks/guard_common.py`](https://github.com/pixelofsoftware/AI-Mods/blob/main/.claude/hooks/guard_common.py) |

Legend: ⛔ Deny/Block · ✋ Ask · ⚠️ Warn · ✅ Allow

## What it checks

| Tool | Inputs checked |
|---|---|
| `Read` | `file_path` |
| `NotebookRead` | `notebook_path` |
| `Grep` | `path`, and `glob` (the file filter). Not `pattern`, which is a regex over file contents |
| `Glob` | `path` and `pattern` (for Glob, the pattern is a path) |

Each value goes through `looks_secret()` from `guard_common.py`. It's true when the value matches the shared secret-path pattern (with `~` treated as a home directory) or is a glob that expands to secrets (`.env*`, `.env.{prod,local}`, `*.pem`, `*.key`, `*.p12`, `*.pfx`).

## `secret_file_read`

⛔ **Deny.** The path or glob names secret material:

| Kind | Denied | Still readable |
|---|---|---|
| Environment files | `.env`, `.env.<anything>`, `.envrc` | `.env.example`, `.env.sample`, `.env.template`, `.env.dist`, `.env.defaults` |
| Keys and keystores | `id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519`; `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.jks`, `*.keystore`, `*.kdbx`, `*.ppk` | |
| Credential directories | anything under `.ssh/`, `.aws/`, `.gnupg/`, `.kube/`, `.docker/`, `.azure/`, `.config/gcloud/` (including public keys in `~/.ssh`) | |
| Credential files | `.netrc`, `.npmrc`, `.pypirc`, `.pgpass`, `.git-credentials`; `credentials.json`, `client_secret(s).json`, `service-account*.json` | |
| Other | `*.tfstate`, `*.tfstate.backup`, anything under `secret/` or `secrets/`, `kubeconfig*`, `/proc/<pid>/environ`, `/etc/shadow`, `/etc/gshadow`, `/etc/sudoers` | `/etc/passwd` |

Real outputs:

```text
Read(.env.prod)                      ⛔ [AI guardrail] reading `.env.prod` is blocked: it may contain secrets. Use the matching .example file, or ask the developer for the non-secret value you need.
Read(~/.ssh/id_ed25519)              ⛔ reading `id_ed25519` is blocked: …
Read(infra/terraform.tfstate)        ⛔ reading `terraform.tfstate` is blocked: …
Grep(pattern "API_KEY", glob ".env*") ⛔ reading `.env*` is blocked: …
Glob(**/.env)                        ⛔ reading `.env` is blocked: …
Glob(.env.{prod,local})              ⛔ reading `.env.{prod,local}` is blocked: …
Glob(**/*.pem)                       ⛔ reading `*.pem` is blocked: …

Read(.env.example)                   ✅
Read(src/app.py)                     ✅
Glob(**/*.py)                        ✅
```

The reason shows only the base name of the file, not the full path.

**Why.** Read-only tools need no approval inside the workspace, so they're the easiest way for a secret to reach Claude's context. Prompt injection in a file Claude reads can ask it to "check the config in `.env`".

**False positive?** Use the `.example` template, or ask the developer for the specific non-secret value. A non-secret file that happens to live under `secrets/` or match a key extension is still denied: rename it, or read it yourself. Don't widen the exceptions locally; see [False positives and exceptions](Use-Case-False-Positives-and-Exceptions).

## Limits

- **It checks arguments, not the files a search opens.** `Grep` with `path: "."` and a regex such as `API_KEY` isn't denied by this hook, even though the search walks the whole repository. The `Read(...)` deny rules in `.claude/settings.json`, `blockReadsOutsideWorkingDirectories` and the sandbox's filesystem limits are the other layers. See [Project settings](Settings-Project).
- **Shell reads are a different hook.** `cat .env` goes through the [Bash guard](Guardrail-Bash-Guard#secret_file_access), which uses the same path list.
- **It's a path pattern.** A secret stored in a file with an ordinary name (`config.yaml`) isn't recognised. Keep secrets in environment variables or a secret manager.

See [Limitations and threat model](Limitations-and-Threat-Model).

## When the hook itself fails

| Failure | Decision and reason |
|---|---|
| `guard_common` can't be imported | ✋ `[AI guardrail] read_guard could not load its rules (<ErrorType>); manual review required` |
| Any error while running, such as malformed event JSON | ✋ `[AI guardrail] read_guard error (<ErrorType>); manual review required` |

## Audit record

```json
{"@timestamp": "2026-10-28T06:19:39.477744+00:00", "decision": "deny", "event": "PreToolUse", "hook": "read_guard", "permission_mode": "default", "rules": ["secret_file_read"], "session_id": "s-123", "target": ".env.prod", "tool": "Read", "user": "dev"}
```

`target` is the base name only. See [Audit logs](Audit-Logs).

## Try it

```bash
echo '{"tool_name":"Read","tool_input":{"file_path":".env"}}' \
  | CLAUDE_GUARDRAIL_AUDIT=0 python3 .claude/hooks/read_guard.py
```

## Related pages

- [Bash guard](Guardrail-Bash-Guard)
- [File guard](Guardrail-File-Guard)
- [Project settings](Settings-Project)
- [Sensitive data](Use-Case-Sensitive-Data)
- [Limitations and threat model](Limitations-and-Threat-Model)
