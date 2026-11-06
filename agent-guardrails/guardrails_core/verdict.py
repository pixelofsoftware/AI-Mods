"""The host-independent result of a guard."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Verdict:
    """What a guard decided about one action.

    decision: "deny", "ask", or None (no opinion: the host's normal permission flow decides).
    reason:   message for the user and the agent, without the "[AI guardrail] " prefix.
    rules:    rule names, recorded in the audit log.
    audit:    extra metadata-only fields for the audit record (never content).
    """

    decision: Optional[str] = None
    reason: str = ""
    rules: List[str] = field(default_factory=list)
    audit: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PromptVerdict:
    """What the prompt guard decided about one prompt.

    blocked:  the prompt must not reach the model; `reason` explains why and
              carries the redacted copy the user can resubmit.
    notes:    non-blocking notices (personal data, acknowledgement, injection).
    context:  guidance for the model when there are notes.
    redacted: the prompt with blocked categories masked.
    audits:   (decision, rules, extra) records to write, in order.
    """

    blocked: bool = False
    reason: str = ""
    notes: List[str] = field(default_factory=list)
    context: str = ""
    redacted: str = ""
    audits: List[tuple] = field(default_factory=list)
