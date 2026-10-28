This page is for developers building a service on the Claude API in Python. It walks through putting `SafeClaude` from [`scripts/claude_safeguard.py`](https://github.com/pixelofsoftware/AI-Mods/blob/main/scripts/claude_safeguard.py) in front of every call: installation, secrets, a full example, handling blocked and unsafe results, tool use, tuning the thresholds, Bedrock and Vertex, shipping audit events and testing.

For the internals of each layer, see [API safeguard](Guardrail-API-Safeguard).

## What `SafeClaude` does on every call

1. **Redacts** every user-content string: the system prompt, message text, `tool_result` content, text documents and `tool_use` inputs. The same value always gets the same placeholder within a request (`[REDACTED:EMAIL_1]`).
2. **Refuses locally** when the most severe finding is at or above the block threshold (default: CRITICAL, meaning credentials). Nothing is sent.
3. **Hardens the request**: it appends an anti-injection preamble and a random canary token to the system prompt.
4. **Sends** to `claude-opus-5-5` (configurable), with server-side refusal fallback on by default.
5. **Validates the response** text and every `tool_use` input. Reverse shells, encoded execution, `rm -rf /`, disk wipes, credential exfiltration, markdown-image exfiltration, invisible Unicode, leaked secrets and the canary are BLOCK; `curl | sh`, `chmod 777`, security-control bypasses, chat-template tokens and injection echoes are WARN.
6. **Writes one JSON audit line** to stdout. It never contains the raw prompt.

## 1. Install

```bash
python3 -m pip install "anthropic>=2.3,<3"
```

Or, from a clone of this repository, `scripts/setup_guardrails.sh --with-sdk`. Scanning needs only the standard library; the SDK is imported lazily on the first real call.

Then either vendor the single file into your service (for example `yourapp/claude_safeguard.py`) or add `scripts/` to `PYTHONPATH`. If you vendor it, pin the commit you copied and note it, so you can pick up detector fixes later.

## 2. Keep the API key out of code

- In production, inject `ANTHROPIC_API_KEY` from your secret manager (Vault, AWS Secrets Manager, GCP Secret Manager) at runtime.
- Never put it in code, config files, container images or logs.
- For local development, `ant auth login` stores a profile the SDK picks up automatically.

`SafeClaude()` with no `client` argument creates a default `anthropic.Anthropic()` client, which reads those credentials from the environment.

## 3. A complete example

```python
import logging

from claude_safeguard import SafeClaude, PromptBlockedError, UnsafeOutputError

log = logging.getLogger("support")

# One instance per process is fine; each create() call gets its own redaction map.
guard = SafeClaude(app_name="support-assistant")


def summarise_ticket(current_user, ticket_text: str) -> str:
    try:
        result = guard.create(
            user_id=current_user.id,  # attributed in the audit event
            system="You summarise support tickets for agents.",
            messages=[{"role": "user", "content": ticket_text}],
            max_tokens=4096,
        )
    except PromptBlockedError as exc:
        # Credentials in the input. Nothing was sent to the API.
        log.warning("prompt blocked: %s", exc.report["event"]["reason"])
        return "This ticket contains credentials and was not sent. Remove them and try again."
    except UnsafeOutputError as exc:
        # The reply failed validation. exc.report says why; exc.request_id matches the audit event.
        log.warning("unsafe output %s request=%s", exc.report.counts(), exc.request_id)
        return "The response failed a safety check."

    if result.refused:
        return "Claude declined this request."

    if result.output.verdict.value == "WARN":
        log.info("output warnings %s", result.output.counts())

    return result.text  # placeholders such as [REDACTED:EMAIL_1] stay masked
```

What you get back in `SafeResult`:

| Field | Meaning |
|---|---|
| `text` | The text blocks joined, still with placeholders. Sanitised if `output_action` is `sanitize` |
| `request_id` | The UUID used as `event.id` in the audit line |
| `risk_level` | Highest input severity: `LOW`, `MEDIUM`, `HIGH` or `CRITICAL` |
| `input_findings` | Counts per category, for example `{"EMAIL": 1}` |
| `output` | The `OutputReport`: `verdict`, `findings`, `sanitized_text`, `counts()` |
| `refused` | `True` when `stop_reason` is `refusal` |
| `message` | The raw SDK response, for `stop_reason`, `content`, `usage` and so on |
| `rehydrated_text()` | The text with original values put back. **Only** for showing to the same user who supplied them. Never log it |

## 4. Handle every outcome in the UI

| Outcome | How you detect it | What to show |
|---|---|---|
| Credentials in the input | `PromptBlockedError` | "This request contains credentials and was not sent." `exc.report` is the audit event, with `event.outcome = "blocked"` and `event.reason` |
| Unscannable input refused | `PromptBlockedError` when `CLAUDE_SAFEGUARD_BLOCK_UNSCANNABLE=1` and the request has images or PDFs | "Attachments can't be checked for sensitive data." |
| Unsafe reply | `UnsafeOutputError` (default `raise`) | A generic failure. Don't show the raw reply |
| Model declined | `result.refused` | "Claude declined this request." `result.message.stop_details.category` says why, when present |
| Reply with warnings | `result.output.verdict.value == "WARN"` | Show it, but don't auto-execute anything it suggests |
| API or network error | The SDK's own exception, re-raised after an audit event with `event.outcome = "failure"` | Your normal retry or error path |

Whatever the verdict, treat model output as untrusted input: never pipe it into a shell, `eval`, SQL or HTML without validation and encoding ([policy §6](https://github.com/pixelofsoftware/AI-Mods/blob/main/docs/claude-guardrails.md#6-building-applications-with-the-claude-api)).

## 5. Tool use

Pass tools through `create()`; extra keyword arguments go straight to the Messages API. Every `tool_use` block in the response is validated like text, and the findings are prefixed `tool_input:`.

```python
TOOLS = [{
    "name": "lookup_order",
    "description": "Look up an order by its ID.",
    "input_schema": {
        "type": "object",
        "properties": {"order_id": {"type": "string"}},
        "required": ["order_id"],
    },
}]

messages = [{"role": "user", "content": question}]
for _ in range(10):  # always bound the loop
    result = guard.create(user_id=user.id, messages=messages, tools=TOOLS, max_tokens=4096)
    if result.message.stop_reason != "tool_use":
        break
    messages.append({"role": "assistant", "content": result.message.content})
    tool_results = []
    for block in result.message.content:
        if block.type == "tool_use":
            output = run_tool(block.name, block.input)  # validate block.input before acting on it
            tool_results.append({"type": "tool_result", "tool_use_id": block.id, "content": output})
    messages.append({"role": "user", "content": tool_results})  # all results in one message

answer = result.text
```

Things to know:

- **A blocked tool input always raises** `UnsafeOutputError`, even when `output_action` is `sanitize`, because a tool call can't be sanitised in place. Only `warn` lets it through, and then your code must decide.
- **Each call re-scans the whole history.** `tool_result` content is redacted too, so a tool that returns customer emails gets them masked before they're sent. A credential returned by a tool blocks that call and every later call that carries the same history.
- `SafeResult.text` only contains text blocks. Look at `result.message.content` for `tool_use` blocks.
- Passing the SDK's response blocks back in `messages` works; the wrapper converts them before scanning. `thinking` and `redacted_thinking` blocks are passed through untouched.
- On current Opus models, forced `tool_choice` (`any` or `tool`) isn't supported. Use `auto` and name the tool in the prompt.

## 6. Choose the thresholds

Configure with environment variables, or pass a `Policy` object.

| Variable | Default | Meaning |
|---|---|---|
| `CLAUDE_SAFEGUARD_MODEL` | `claude-opus-5-5` | Model ID |
| `CLAUDE_SAFEGUARD_BLOCK_ON` | `critical` | Lowest severity that refuses the request locally: `critical`, `high`, `medium`, or `none` (redact only) |
| `CLAUDE_SAFEGUARD_REDACT_MIN` | `medium` | Lowest severity that gets masked |
| `CLAUDE_SAFEGUARD_OUTPUT_ACTION` | `raise` | On BLOCK: `raise`, `sanitize` or `warn` |
| `CLAUDE_SAFEGUARD_FALLBACKS` | `1` | Server-side refusal fallback |
| `CLAUDE_SAFEGUARD_CANARY` | `1` | System-prompt leak canary |
| `CLAUDE_SAFEGUARD_HARDEN_SYSTEM` | `1` | Anti-injection preamble |
| `CLAUDE_SAFEGUARD_BLOCK_UNSCANNABLE` | `0` | `1` refuses images and PDFs, which regex can't scan |
| `CLAUDE_SAFEGUARD_TRUSTED_IMAGE_HOSTS` | empty | Comma-separated hosts whose markdown images are allowed |
| `CLAUDE_SAFEGUARD_APP` | `claude-app` | `service.name` in audit events (`app_name=` overrides it) |

Severity levels, from [Detectors reference](Detectors-Reference):

| Severity | Detectors |
|---|---|
| CRITICAL | Private keys, cloud and API keys, bearer tokens, passwords in URLs |
| HIGH | JWTs, `password=` style assignments, SSNs, card numbers, IBANs, medical record numbers |
| MEDIUM | Emails, phone numbers |

Note that JWTs and `password=` assignments are HIGH, so with the default `BLOCK_ON=critical` they're **redacted and sent**, not refused.

Suggested profiles:

| Workload | `BLOCK_ON` | `REDACT_MIN` | `OUTPUT_ACTION` | `BLOCK_UNSCANNABLE` |
|---|---|---|---|---|
| Internal developer tool | `critical` | `medium` | `raise` | `0` |
| Customer-facing support assistant | `critical` | `medium` | `sanitize` | `0` |
| Regulated data (health, finance) | `high` | `medium` | `raise` | `1` |
| Redaction-only pipeline where you've accepted the risk | `none` | `medium` | `raise` | `0` |

In code:

```python
from claude_safeguard import Policy, SafeClaude, Severity

guard = SafeClaude(policy=Policy(
    block_min_severity=Severity.HIGH,
    output_action="sanitize",
    block_unscannable=True,
    app_name="claims-assistant",
))
```

With `sanitize`, blocked spans in the text are replaced with `[REMOVED:<rule>]`. With `warn`, the original text comes back and only the audit event and `result.output` record the problem.

## 7. Amazon Bedrock and Google Vertex AI

Pass your own client, and **turn fallbacks off**: server-side refusal fallback isn't available on Bedrock, Vertex AI or Microsoft Foundry.

```bash
export CLAUDE_SAFEGUARD_FALLBACKS=0
```

Bedrock (model IDs take the `anthropic.` prefix):

```python
import anthropic
from claude_safeguard import SafeClaude

guard = SafeClaude(
    client=anthropic.AnthropicBedrockMantle(aws_region="eu-central-1"),
    app_name="support-assistant",
)
# CLAUDE_SAFEGUARD_MODEL=anthropic.claude-opus-5-5
```

Vertex AI (install `"anthropic[vertex]"`; current model IDs have no prefix):

```python
import anthropic
from claude_safeguard import SafeClaude

guard = SafeClaude(
    client=anthropic.AnthropicVertex(project_id="my-gcp-project", region="global"),
    app_name="support-assistant",
)
# CLAUDE_SAFEGUARD_MODEL=claude-opus-5-5
```

With fallbacks off, the wrapper calls `client.messages` instead of `client.beta.messages` and sends no fallback beta header.

## 8. Ship the audit events

Every call writes one line to stdout. A line from a tool-use turn (IDs shortened, token counts and timing illustrative):

```json
{"@timestamp":"2026-10-28T06:17:42.518096+00:00","claude":{"anthropic_request_id":"req_…","fallback_used":false,"fallbacks_enabled":true,"model_requested":"claude-opus-5-5","model_served":"claude-opus-5-5","stop_reason":"tool_use","usage":{"cache_read_input_tokens":0,"input_tokens":812,"output_tokens":164}},"duration_ms":2310.4,"event":{"action":"claude.messages.create","category":["web"],"dataset":"claude_safeguard.audit","id":"72539ea6-…","kind":"event","outcome":"success","type":["access"]},"output":{"action":"raise","findings":{},"verdict":"PASS"},"prompt":{"messages":1,"sha256":"d114fbb2…"},"risk":{"input_findings":{"EMAIL":1},"invisible_chars_removed":0,"level":"MEDIUM","prompt_injection_signals":[],"redactions":1,"unscannable_blocks":0},"service":{"name":"support-assistant"},"user":{"id":"u-1234"}}
```

- Field names follow ECS conventions, so Elastic, Splunk, Sentinel and Datadog parse them with a JSON source type.
- Collect stdout with your usual agent (Fluent Bit, Vector, Datadog Agent).
- `prompt.sha256` is a hash of the **redacted** text. The raw prompt is never logged.
- `event.outcome` is `success`, `blocked` or `failure`. Alert on `blocked`, on `output.verdict = "BLOCK"`, and on non-empty `risk.prompt_injection_signals`.
- To send events somewhere else, pass `audit=AuditLogger(stream=your_stream)`.

## 9. Test without spending tokens

Dry-run your inputs and outputs with the CLI. Neither command calls the API.

```bash
python3 scripts/claude_safeguard.py scan "Refund jane@corp.com, card 4012 8888 8888 1881"   # exit 2 if it would be blocked
python3 scripts/claude_safeguard.py check-output < model_reply.txt                         # exit 2 on BLOCK
```

`scan` respects `CLAUDE_SAFEGUARD_BLOCK_ON`, so you can preview a stricter policy:

```bash
CLAUDE_SAFEGUARD_BLOCK_ON=high python3 scripts/claude_safeguard.py scan "SSN 123-45-6789"   # would_block: true, exit 2
```

A `check-output` result for a reply that suggests piping a download into a shell:

```json
{
  "verdict": "WARN",
  "findings": [
    {"rule": "pipe_to_shell", "verdict": "WARN", "description": "remote script piped into a shell"}
  ],
  "sanitized_text": null
}
```

One guarded live call, when you're ready:

```bash
python3 scripts/claude_safeguard.py ask --user "$USER" "Explain this stack trace: …"
```

Here the audit line goes to stderr so stdout carries only the answer. Exit codes: `0` success, `2` prompt blocked, `3` unsafe output, `4` refusal.

In unit tests, inject a fake client, as the repository's own tests do in [`tests/test_safeguard.py`](https://github.com/pixelofsoftware/AI-Mods/blob/main/tests/test_safeguard.py): `SafeClaude(client=fake, policy=Policy(...), audit=AuditLogger(stream=io.StringIO()))`. Build any credential-shaped test strings at runtime (see [`tests/conftest.py`](https://github.com/pixelofsoftware/AI-Mods/blob/main/tests/conftest.py)).

## Before you go live

- [ ] Every Claude call goes through `SafeClaude` (or a reviewed equivalent).
- [ ] The API key comes from the secret manager at runtime.
- [ ] `user_id` is the real end-user or service identity.
- [ ] Refusals, blocked prompts and unsafe output each have a UI path.
- [ ] Audit lines reach the SIEM, with alerts on `blocked` and `BLOCK`.
- [ ] Fallbacks are off on Bedrock, Vertex or Foundry.
- [ ] Architecture review is done if you handle personal, health or financial data, including data residency and retention.

## Related pages

- [API safeguard](Guardrail-API-Safeguard)
- [Detectors reference](Detectors-Reference)
- [Environment variables](Settings-Environment-Variables)
- [Sensitive data](Use-Case-Sensitive-Data)
- [Limitations and threat model](Limitations-and-Threat-Model)
