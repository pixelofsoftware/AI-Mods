"""Host-independent guardrail engine shared by the Claude Code, Cursor and Copilot adapters.

Standard library only. Each guard returns a decision; the adapters in
../adapters translate host events into calls here and decisions back into the
host's hook format.
"""

from .files import evaluate_read, evaluate_write
from .prompt import evaluate_prompt
from .shell import evaluate_shell
from .verdict import PromptVerdict, Verdict

__all__ = ["evaluate_shell", "evaluate_write", "evaluate_read", "evaluate_prompt", "Verdict", "PromptVerdict"]
__version__ = "0.1.0"
