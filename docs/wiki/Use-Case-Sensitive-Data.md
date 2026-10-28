This page is for anyone who works near credentials or personal data: debugging a failing login, writing parsers for customer records, building test fixtures. It shows what the guards do when sensitive data shows up, how to work with synthetic data without friction, and what to do if something real slipped through.

## The rule, in one line

Never put credentials, customer or employee personal data, health data or unscrubbed production data into a prompt, a pasted file, an MCP request or a Claude API call. The tooling is a safety net, not the control: detection is pattern-based and **won't** catch free-text personal data such as a patient's name and diagnosis written in prose. Source: [policy §2](https://github.com/pixelofsoftware/AI-Mods/blob/main/docs/claude-guardrails.md#2-data-protection).

## What the prompt guard does

`prompt_guard` checks every prompt before it reaches Claude. It sorts what it finds into three groups:

| Found | Examples | Action | Override |
|---|---|---|---|
| **Credentials** | Private keys; Anthropic, OpenAI, AWS, GCP, Azure, GitHub, GitLab, Slack and Stripe keys; bearer tokens; JWTs; passwords in URLs; `password=` style assignments | ⛔ Block | **None** |
| **Regulated personal data** | US SSNs, card numbers (Luhn-checked), IBANs (mod-97 checked), medical record numbers | ⛔ Block | `[sensitive-ok: reason]` |
| **Contact data** | Email addresses, phone numbers | ⚠️ Notice | Not needed |
| **Prompt-injection signals** | "ignore previous instructions", role hijacks, system-prompt probes | ⚠️ Warning | Not needed |

Every detector is listed on [Detectors reference](Detectors-Reference); the hook itself is on [Prompt guard](Guardrail-Prompt-Guard).

## Walkthrough: a blocked prompt and the redacted copy

### Step 1: You paste a key while debugging

You type something like `Why does auth fail? key=sk-ant-api03-…` (with a real-looking 40-character key).

⛔ The prompt is blocked before it reaches Claude:

```text
Blocked by AI data-protection policy: the prompt contains API_KEY.
Credentials must never be sent to an AI service. If the value is real, rotate it now.

Redacted version you can resubmit:

Why does auth fail? key=[REDACTED:API_KEY_1]
```

### Step 2: Resubmit the redacted copy

Copy the redacted version and send it. Claude can still reason about it: the placeholder tells it a key was there. `CLAUDE.md` tells Claude that placeholders like `[REDACTED:API_KEY_1]` are intentional and not to guess the original.

### Step 3: If the key was real, rotate it

The guard stopped the prompt from reaching Claude, but the value still went through your clipboard and your terminal. If it's real, rotate it. If you're not sure whether anything was sent, follow [Incident response](Use-Case-Incident-Response).

> The organisation policy may log prompts centrally through OpenTelemetry. Whether Claude Code emits the prompt event before a hook blocks the prompt isn't documented, so the setup guide tells admins to assume it can and to redact at the collector. One more reason to rotate.

### Personal data looks the same

A prompt with a synthetic SSN and card number:

```text
Blocked by AI data-protection policy: the prompt contains CARD_NUMBER, SSN.
If this is synthetic test data, add [sensitive-ok: <reason>] to the prompt to proceed (logged).

Redacted version you can resubmit:

Parse this record: SSN [REDACTED:SSN_1], card [REDACTED:CARD_NUMBER_1]
```

Emails and phone numbers don't block. You get a notice instead:

```text
[AI guardrail] Prompt contains EMAIL, PHONE; avoid customer personal data in prompts (policy §2).
```

Claude also receives a note telling it not to repeat personal data verbatim.

## `[sensitive-ok: reason]`: what it unlocks

Add the acknowledgement anywhere in the prompt when the data is synthetic:

```text
[sensitive-ok: synthetic fixture for parser tests] Parse this record: SSN 123-45-6789, card 4012 8888 8888 1881
```

✅ The prompt goes through, and you see:

```text
[AI guardrail] Sensitive-data acknowledgement recorded (CARD_NUMBER, SSN).
```

The audit log records an `allow_with_ack` event with your reason:

```json
{"ack_reason": "synthetic fixture for parser tests", "decision": "allow_with_ack", "hook": "prompt_guard", "rules": ["us_ssn"], ...}
```

| It unlocks | It never unlocks |
|---|---|
| SSN, card number, IBAN, medical record number (`PHI`) | Any credential: `API_KEY`, `CLOUD_CREDENTIAL`, `AUTH_TOKEN` (including JWTs and bearer tokens), `PASSWORD` (including `password=` and passwords in URLs), `PRIVATE_KEY` |
| | Anything in a file write (the file guard ignores it) |
| | Real customer data. The tag is a statement that the data is synthetic; it's audited |

Two details that trip people up:

- **The reason must be 5 to 200 characters.** `[sensitive-ok: ok]` is too short, so the prompt stays blocked.
- **A credential still blocks with the tag present.** For example, `[sensitive-ok: synthetic fixture] use key sk-ant-api03-…` is blocked with *Credentials must never be sent to an AI service*. Use a placeholder instead.

## Synthetic data that doesn't trigger anything

The detectors skip well-known test values and placeholders, so you often don't need the tag at all. These were checked against the current detectors with `scan`:

| Need | Use | Result |
|---|---|---|
| An API key in an example | `<ANTHROPIC_API_KEY>`, `${API_KEY}`, `{{ api_key }}` | ✅ Not flagged |
| A password in config | `password=changeme`, `password = ${DB_PASSWORD}`, `password = "<PASSWORD>"` | ✅ Not flagged |
| A bearer token | `Authorization: Bearer ${TOKEN}` | ✅ Not flagged |
| An AWS key ID | `AKIAIOSFODNN7EXAMPLE` (AWS's documented example) | ✅ Not flagged |
| A card number | Card-network test numbers such as `4242 4242 4242 4242` or `4111111111111111` | ✅ Not flagged |
| An SSN | A number in a range the SSA never issues, such as `987-65-4320` (area `9xx`) | ✅ Not flagged |
| An IBAN | One with a wrong checksum, such as `DE00 3704 0044 0532 0130 00` | ✅ Not flagged |
| An email | `jane.doe@example.com` | ⚠️ Notice only |
| A phone number | `+1 555 010 0199` | ⚠️ Notice only |

Values that **do** need care:

- `sk-ant-` followed by 20 or more key characters is always flagged, even if you made it up. In docs, truncate it: `sk-ant-api03-…`.
- Luhn-valid card numbers that aren't on the test list (for example `4012 8888 8888 1881`) and valid-format SSNs (`123-45-6789`) are flagged as real. Use them only with `[sensitive-ok: …]`.

## Fixtures and test files

`file_guard` checks the content of every `Write` and `Edit`:

| Content | Action | Example message |
|---|---|---|
| A hardcoded credential | ⛔ Deny | ``hardcoded credential detected (API_KEY) in `src/client.py`. Read it from an environment variable or the secret manager instead, and rotate the value if it is real.`` |
| A password in a URL | ⛔ Deny | ``hardcoded credential detected (PASSWORD) in `tests/test_db.py`. …`` |
| An SSN, card, IBAN, MRN, JWT or `password=` assignment | ✋ Ask | ``` `tests/fixtures/users.json`: content contains likely secrets or regulated personal data (SSN); use obviously synthetic fixtures ``` |
| Emails, phone numbers, placeholders | ✅ Silent | |

So for fixtures:

1. Prefer values from the "doesn't trigger" table above.
2. If a test really needs a valid-format SSN or card number, approve the ✋ prompt after checking the data is synthetic.
3. If a test needs a credential-shaped string (for example to test a detector), build it at runtime so no literal key sits in the file. This repository does it in [`tests/conftest.py`](https://github.com/pixelofsoftware/AI-Mods/blob/main/tests/conftest.py):

   ```python
   anthropic_key = "sk-ant-" + "api03-" + "Zq9xLm2Pw7" * 5
   ```

4. Read real credentials in code from the environment: `os.environ["ANTHROPIC_API_KEY"]` passes every check.

At commit time, `scan-ai-secrets` and `gitleaks` catch any credential that got past the editor.

## `.env.example` vs `.env`

| File | Claude can read | Claude can write | Can be committed |
|---|---|---|---|
| `.env`, `.env.local`, `.env.production`, `.env.prod`, any other `.env.*`, `.envrc` | ⛔ No | ⛔ No | ⛔ No (`forbid-ai-artifacts`, `.gitignore`) |
| `.env.example`, `.env.sample`, `.env.template`, `.env.dist`, `.env.defaults` | ✅ Yes | ✅ Yes | ✅ Yes |

What you'll see if Claude tries the secret file:

```text
[AI guardrail] reading `.env.prod` is blocked: it may contain secrets. Use the matching .example file, or ask the developer for the non-secret value you need.
```

```text
[AI guardrail] `config/.env.production` is a secrets file. The AI agent may not create or edit it; update the matching `.example` template and let a human fill real values.
```

The same goes for the shell (`cat .env`, `source .env`, `grep … .env`, `cp .env …`), for `Glob` patterns like `**/.env*`, and for keys, kubeconfigs, Terraform state, `~/.ssh`, `~/.aws` and other credential stores. `env`, `printenv` and `echo $AWS_SECRET_ACCESS_KEY` are denied too.

The working pattern:

1. Keep every variable name, with a fake or empty value, in `.env.example`. Claude can read and update it.
2. Fill real values in `.env` yourself.
3. If Claude needs a non-secret value (a port, a feature flag), tell it in the prompt.

## Check text with `scan` before you paste it

Before you paste a log, a stack trace or a ticket, run it through the scanner. It runs offline: no API call, no network.

```bash
python3 scripts/claude_safeguard.py scan "Refund jane@corp.io, SSN 123-45-6789, card 4012 8888 8888 1881"
```

```json
{
  "risk_level": "HIGH",
  "would_block": false,
  "findings": [
    {"rule": "email", "category": "EMAIL", "severity": "MEDIUM"},
    {"rule": "us_ssn", "category": "SSN", "severity": "HIGH"},
    {"rule": "payment_card", "category": "CARD_NUMBER", "severity": "HIGH"}
  ],
  "prompt_injection_signals": [],
  "invisible_chars_removed": 0,
  "redacted_text": "Refund [REDACTED:EMAIL_1], SSN [REDACTED:SSN_1], card [REDACTED:CARD_NUMBER_1]"
}
```

For a file, pipe it in: `python3 scripts/claude_safeguard.py scan - < app.log`.

How to read it:

- `redacted_text` is a safe version you can paste.
- `would_block` and the exit code (2 when blocked) follow the **API safeguard** policy, which by default blocks only CRITICAL findings (credentials). The **prompt guard** is stricter: it also blocks HIGH findings such as SSNs and cards. So treat any HIGH or CRITICAL `risk_level` as "the prompt guard will block this".
- `prompt_injection_signals` warns you that the text contains instructions aimed at an AI, which matters when you paste content from issues, web pages or emails.

Claude can run `scan` too: it's on the allowlist.

## If something real was sent

1. **Rotate it first.** A credential that reached any AI service, log or chat is compromised. Revoke and reissue it now, before anything else.
2. **Report it** in your incident channel (`#security-incidents` in the template; your organisation's channel name will differ) with the time and your Claude Code session ID. The session ID is in your audit log (`session_id`). Reporting quickly is never penalised.
3. **Don't try to clean up quietly.** Transcripts and central logs may hold a copy; security needs to know.

The full procedure, including what evidence exists, is on [Incident response](Use-Case-Incident-Response).

## Related pages

- [Prompt guard](Guardrail-Prompt-Guard)
- [Detectors reference](Detectors-Reference)
- [Read guard](Guardrail-Read-Guard)
- [File guard](Guardrail-File-Guard)
- [Incident response](Use-Case-Incident-Response)
- [Limitations and threat model](Limitations-and-Threat-Model)
