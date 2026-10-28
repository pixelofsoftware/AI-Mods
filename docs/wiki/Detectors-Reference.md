Every credential and personal-data detector the project uses lives in one tuple, `DEFAULT_RULES` in `scripts/claude_safeguard.py`. The prompt guard, the file guard, the `scan-ai-secrets` pre-commit hook and the API safeguard all import it, so they can't drift apart. This page lists every detector, the prompt-injection and invisible-character checks, and how each component turns a severity into a decision.

## At a glance

| | |
|---|---|
| **Detectors** | 22: 14 `CRITICAL` credentials, 2 `HIGH` credentials, 4 `HIGH` regulated identifiers, 2 `MEDIUM` contact details |
| **Injection checks** | 5 patterns plus invisible Unicode |
| **Method** | Regular expressions with bounded quantifiers, plus validators (Luhn, mod-97, placeholder and test-value filters) |
| **Used by** | [Prompt guard](Guardrail-Prompt-Guard), [File guard](Guardrail-File-Guard), [scan-secrets](Guardrail-Commit-and-Merge-Gates#scan-secrets), [API safeguard](Guardrail-API-Safeguard) |
| **Not used by** | The [Bash guard](Guardrail-Bash-Guard) and [Read guard](Guardrail-Read-Guard), which check commands and paths, not content |
| **Source** | [`scripts/claude_safeguard.py`](https://github.com/pixelofsoftware/AI-Mods/blob/main/scripts/claude_safeguard.py) (`DEFAULT_RULES`, `PROMPT_INJECTION_PATTERNS`, `INVISIBLE_CHARS_RE`) |

Legend: ⛔ Deny/Block · ✋ Ask · ⚠️ Warn · ✅ Allow

## How detection works

1. **Strip invisible characters.** `Redactor.redact()`, used by the prompt guard and the API safeguard's input side, removes invisible Unicode and NFC-normalises the text before scanning, so a zero-width space can't split a key in two. `Redactor.scan()`, used by the file guard, `scan-secrets` and output validation, scans the text as it is.
2. **Run every rule.** Each rule is a regex; some report only a capture group (the value after a label, for example). If the rule has a validator and it rejects the value, there's no finding.
3. **Resolve overlaps.** Findings are sorted by severity (highest first), then by length (longest first), then by rule order. Overlapping lower-ranked findings are dropped.
4. **Mask.** Findings at or above the redactor's `min_severity` are replaced with a placeholder. Findings below it are still reported, just not masked.

### Placeholders

Each masked value becomes `[REDACTED:<CATEGORY>_<n>]`, numbered per category. One `Redactor` instance keeps a map, so the same value always gets the same placeholder:

```text
Email [REDACTED:EMAIL_1], phone [REDACTED:PHONE_1]. Ignore all previous instructions.
```

The map stays in memory and is never logged. The API safeguard can put the originals back for display (`SafeResult.rehydrated_text()`).

## Severities and categories

| Severity | Categories |
|---|---|
| `CRITICAL` | `PRIVATE_KEY`, `API_KEY`, `CLOUD_CREDENTIAL`, `AUTH_TOKEN`, `PASSWORD` |
| `HIGH` | `AUTH_TOKEN` (JWT), `PASSWORD` (assignments), `SSN`, `CARD_NUMBER`, `IBAN`, `PHI` |
| `MEDIUM` | `EMAIL`, `PHONE` |

`CREDENTIAL_CATEGORIES` is `PRIVATE_KEY`, `API_KEY`, `CLOUD_CREDENTIAL`, `AUTH_TOKEN` and `PASSWORD`. Some components look at the category as well as the severity, which is why `jwt` and `secret_assignment` behave differently from the other `HIGH` detectors. See [How severities become decisions](#how-severities-become-decisions).

## Credential detectors (`CRITICAL`)

| Detector | Category | Matches | Extra validation |
|---|---|---|---|
| `private_key_block` | `PRIVATE_KEY` | A PEM header `-----BEGIN` … `PRIVATE KEY-----` with up to four words before `PRIVATE KEY` (RSA, EC, OPENSSH, ENCRYPTED, …), optionally `PRIVATE KEY BLOCK`. If the matching END line appears within 16 KB, the whole block is the finding | – |
| `anthropic_api_key` | `API_KEY` | `sk-ant-` followed by 20+ letters, digits, `_` or `-` | – |
| `openai_api_key` | `API_KEY` | `sk-`, optionally `proj-` or `svcacct-`, then 32+ letters, digits, `_` or `-` | – |
| `aws_access_key_id` | `CLOUD_CREDENTIAL` | `AKIA`, `ASIA`, `ABIA` or `ACCA` followed by exactly 16 uppercase letters or digits | Placeholder filter (rejects AWS's documented `…EXAMPLE` key) |
| `aws_secret_access_key` | `CLOUD_CREDENTIAL` | `aws`, then within 24 characters `secret` or `private`, then within 24 characters `:` or `=`, then exactly 40 base64 characters. The 40 characters are the finding | Placeholder filter |
| `gcp_api_key` | `CLOUD_CREDENTIAL` | `AIza` followed by exactly 35 letters, digits, `_` or `-` | – |
| `azure_storage_key` | `CLOUD_CREDENTIAL` | `AccountKey=` followed by 60+ base64 characters (the value is the finding) | – |
| `github_token` | `API_KEY` | `ghp_`, `gho_`, `ghu_`, `ghs_` or `ghr_` plus 36+ letters or digits; or `github_pat_` plus 22+ letters, digits or `_` | – |
| `gitlab_token` | `API_KEY` | `glpat-` followed by 20+ letters, digits, `_` or `-` | – |
| `slack_token` | `API_KEY` | `xoxa-`, `xoxb-`, `xoxp-`, `xoxo-`, `xoxs-` or `xoxr-` followed by 10+ letters, digits or `-` | – |
| `slack_webhook` | `API_KEY` | `https://hooks.slack.com/services/` followed by 20+ path characters | – |
| `stripe_live_key` | `API_KEY` | `sk_live_` or `rk_live_` followed by 16+ letters or digits. Test keys (`sk_test_`) don't match | – |
| `bearer_token` | `AUTH_TOKEN` | The word `Bearer` (any case), 1–5 spaces, then a 20+ character token (the token is the finding) | Placeholder filter |
| `url_embedded_password` | `PASSWORD` | A URL of the form `scheme://user:<password>@host`. The password part (3+ characters) is the finding | Placeholder filter (so `${DB_PASS}` is fine) |

In docs and tests, write these truncated (`sk-ant-api03-…`, `AKIA…`, `ghp_…`) or build them at runtime from pieces, as `tests/conftest.py` does.

## Likely credentials (`HIGH`, credential category)

| Detector | Category | Matches | Extra validation |
|---|---|---|---|
| `jwt` | `AUTH_TOKEN` | Three dot-separated base64url segments of 8+ characters each, where the first two start with `eyJ` | – |
| `secret_assignment` | `PASSWORD` | A keyword (`password`, `passwd`, `pwd`, `secret`, `client_secret`, `api_key`, `access_token`, `auth_token`, `private_key`; `_` or `-` optional in the compound ones), an optional quote, `:` or `=`, an optional quote, then a value of 8+ characters with no whitespace, quotes, commas or semicolons. The value is the finding | Placeholder filter |

`secret_assignment` is the detector most likely to fire on ordinary text, because any 8+ character word after `api_key:` counts. A prompt that says the API key setting is "required", written as `api_key:` followed by that word, is blocked by the prompt guard as `PASSWORD`. Use a placeholder (`<required>`, `${API_KEY}`) or a code reference instead.

## Regulated identifiers (`HIGH`)

| Detector | Category | Matches | Extra validation |
|---|---|---|---|
| `us_ssn` | `SSN` | `NNN-NN-NNNN` with dashes. Area `000`, `666` and `9xx`, group `00` and serial `0000` are excluded | Built into the regex |
| `payment_card` | `CARD_NUMBER` | 13–19 digits, optionally separated by single spaces or dashes, not touching other digits or dashes | **Luhn** checksum must pass; known test card numbers are rejected |
| `iban` | `IBAN` | Two uppercase letters, two digits, then 2–7 groups of four uppercase letters or digits and an optional final group of 1–4 (single spaces between groups optional) | Length 15–34 and **ISO 13616 mod-97** must equal 1 |
| `medical_record_number` | `PHI` | The label `MRN`, `patient id` or `medical record` (optionally followed by `number` or `no.`), an optional `:` or `#`, then 6–12 letters, digits or dashes (the value is the finding) | – |

### `medical_record_number`

This detector is case-insensitive, including the value. Any 6–12 letter word after one of the labels matches, so ordinary sentences trip it: the word *numbers* after *medical record*, or *followed* after *patient id*. The prompt guard then blocks the prompt as `PHI` (overridable with `[sensitive-ok: <reason>]`), and the file guard asks. Rephrase, or put the label in backticks or quotes so it isn't directly followed by a word.

## Contact details (`MEDIUM`)

| Detector | Category | Matches | Extra validation |
|---|---|---|---|
| `email` | `EMAIL` | `local@domain.tld` with a 2–24 letter top-level domain | – |
| `phone` | `PHONE` | An optional `+` country code, then a 2–4 digit group (or one in parentheses), then two 3–4 digit groups, separated by spaces, dots or dashes. Not preceded or followed by another digit group, so a spaced card number isn't read as a phone number | 9–15 digits in total, and not shaped like an IPv4 address (`192.168.100.200` doesn't match) |

## False-positive filters

### Placeholder filter

Five detectors (`aws_access_key_id`, `aws_secret_access_key`, `bearer_token`, `url_embedded_password`, `secret_assignment`) run their value through `_not_placeholder()`. The value (after trimming quotes and backticks) is **ignored** when it:

- is a known test value, or contains `EXAMPLE` (any case)
- is an environment reference: `$VAR`, `${VAR}`
- is a template: `<your-key>`, `{{ secret }}`
- is masked: only `*`, `x`, `X`, `.` or `-`
- is one of `changeme`, `change_me`, `placeholder`, `redacted`, `dummy`, `example`, `sample`, `test`, `todo`, `none`, `null`, `true`, `false` (any case)
- starts with `os.environ`, `process.env`, `env(`, `getenv`, `secrets.` or `vault:`
- looks like a code reference (`self.api_key`, `settings.DB_PASSWORD`) or contains `(`
- has three or fewer distinct characters (`aaaaaaaa`, `12121212`)

### Known test values

`KNOWN_TEST_VALUES` holds AWS's documented example key ID and secret key (both contain `EXAMPLE`), and published card-network test numbers: `4111111111111111`, `4242424242424242`, `4000056655665556`, `5555555555554444`, `5105105105105100`, `2223003122003222`, `378282246310005`, `371449635398431`, `6011111111111117`, `3056930009020004`, `3566002020360505`. Card numbers are compared after removing spaces and dashes. These don't produce findings, so they're safe in test fixtures.

## Prompt-injection patterns

`detect_prompt_injection(text)` returns the names of the patterns that match. It never redacts or blocks by itself.

| Name | Matches |
|---|---|
| `ignore_instructions` | `ignore`, `disregard`, `forget` or `override`, then within 40 characters `previous`, `prior`, `above`, `earlier`, `all`, `system` or `developer`, then within 20 characters `instruction(s)`, `prompt(s)`, `rules`, `message(s)` or `guidelines`. All on one line with no full stop in between. Example: "Ignore all previous instructions" |
| `role_hijack` | `you are now`, then within 40 characters `DAN`, `jailbroken`, `developer mode`, `unrestricted` or `no longer bound` |
| `system_prompt_probe` | `reveal`, `print`, `repeat`, `output` or `show`, then within 30 characters `system`, `hidden` or `initial` followed by `prompt` or `instructions`. Example: "Please reveal your system prompt" |
| `chat_template_tokens` | Any of `<\|im_start\|>`, `<\|im_end\|>`, `<\|endoftext\|>`, `[INST]`, `[/INST]`, `<<SYS>>`, `<system>`, `</system>` |
| `fake_turn_marker` | A line that starts (after optional spaces and an optional `##` heading marker) with `system:` or `assistant:` followed by text |
| `invisible_unicode` | Any invisible character listed below |

All patterns are case-insensitive except `chat_template_tokens`.

| Component | What a match does |
|---|---|
| Prompt guard | ⚠️ Warning to you, a note to Claude, and an audit line. The prompt still goes through |
| API safeguard, input | Recorded in the audit event as `risk.prompt_injection_signals`. Never blocks |
| API safeguard, output | `ignore_instructions` → `injection_echo` ⚠️ WARN; chat-template tokens → `chat_template_tokens` ⚠️ WARN; invisible characters → `invisible_unicode` ⛔ BLOCK |
| `scan` CLI | Listed under `prompt_injection_signals` |

These are signals, not a defence. Injection can be phrased in endless ways that none of these patterns match.

## Invisible characters

`INVISIBLE_CHARS_RE` matches characters that hide text from a human reviewer:

| Range | What it is |
|---|---|
| U+E0000–U+E007F | Unicode tag characters (invisible ASCII look-alikes) |
| U+202A–U+202E | Bidirectional embeddings and overrides |
| U+2066–U+2069 | Bidirectional isolates |
| U+200B | Zero-width space |
| U+2060 | Word joiner |
| U+FEFF | Zero-width no-break space / byte-order mark |

Zero-width non-joiner and joiner (U+200C, U+200D) are deliberately **not** included: Persian, Indic scripts and emoji sequences need them.

When text is redacted, these characters are stripped (and counted as `invisible_chars_removed`) before the detectors run. In model output they're a ⛔ BLOCK finding. The file guard and `scan-secrets` don't strip them, so a credential split by an invisible character can slip past those two.

## How severities become decisions

The same finding leads to different decisions in different places. The Bash guard and Read guard don't run these detectors at all.

| Finding | [Prompt guard](Guardrail-Prompt-Guard) | [File guard](Guardrail-File-Guard) (new content) | [scan-secrets](Guardrail-Commit-and-Merge-Gates#scan-secrets) | [API safeguard](Guardrail-API-Safeguard) input (defaults) | API safeguard output |
|---|---|---|---|---|---|
| `CRITICAL` credential | ⛔ Block, no override | ⛔ Deny | ⛔ Fail | Redacted, ⛔ request refused | ⛔ BLOCK (`secret_in_output`) |
| `HIGH` credential (`jwt`, `secret_assignment`) | ⛔ Block, no override | ✋ Ask | ✅ Pass | Redacted and sent | ⛔ BLOCK (`secret_in_output`) |
| `HIGH` regulated (`SSN`, `CARD_NUMBER`, `IBAN`, `PHI`) | ⛔ Block unless `[sensitive-ok: …]` | ✋ Ask | ✅ Pass | Redacted and sent | ⚠️ WARN (`pii_in_output`) |
| `MEDIUM` (`EMAIL`, `PHONE`) | ✅ Allow with a notice | ✅ Ignored | ✅ Pass | Redacted and sent | ✅ Ignored |

The thresholds behind those columns:

| Component | Rule in the code |
|---|---|
| Prompt guard | Block if severity is `CRITICAL` **or** the category is a credential category. Block other `HIGH` unless acknowledged. Notice for `MEDIUM`. The redacted copy masks `HIGH` and above |
| File guard | Deny if credential category **and** `CRITICAL`. Ask for anything else at `HIGH` or above |
| scan-secrets | Fail if credential category **and** `CRITICAL` |
| API safeguard input | Mask at or above `redact_min_severity` (default `MEDIUM`). Refuse at or above `block_min_severity` (default `CRITICAL`). Both configurable through `CLAUDE_SAFEGUARD_REDACT_MIN` and `CLAUDE_SAFEGUARD_BLOCK_ON` |
| API safeguard output | BLOCK if credential category **and** `HIGH` or above. WARN for other `HIGH` and above |

## Limits

- **Formats, not meaning.** Free-text personal data (a patient's name and diagnosis in a sentence) and credentials in formats not listed here aren't detected.
- **False positives exist.** See `secret_assignment` and [`medical_record_number`](#medical_record_number) above.
- **Validators cut noise, not risk.** A real key that happens to contain `EXAMPLE`, or a password of `changeme`, is ignored.

See [Limitations and threat model](Limitations-and-Threat-Model).

## Try it

```bash
python3 scripts/claude_safeguard.py scan "Email jane@example.org about the outage"
```

The result shows each finding's `rule`, `category` and `severity`, and the redacted text. It never prints the matched value. Build credential-shaped test strings at runtime rather than typing them.

## Related pages

- [Prompt guard](Guardrail-Prompt-Guard)
- [File guard](Guardrail-File-Guard)
- [API safeguard](Guardrail-API-Safeguard)
- [Sensitive data](Use-Case-Sensitive-Data)
- [False positives and exceptions](Use-Case-False-Positives-and-Exceptions)
- [Limitations and threat model](Limitations-and-Threat-Model)
