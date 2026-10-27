#!/usr/bin/env python3
"""PreToolUse hook for the Bash tool.

Permission rules match command *text*, so `Bash(curl *)` in deny does not stop
`/usr/bin/curl`, `bash -c 'curl ...'` or `$(curl ...)`. This hook parses the
command, follows wrappers, subshells and `-c` strings, and returns:

  deny -> blocked outright (network egress, secret access, privilege escalation,
          irreversible infra changes, guardrail bypass)
  ask  -> needs explicit human approval even in acceptEdits/auto mode
  (no output) -> normal permission flow from .claude/settings.json

If the hook itself fails it answers "ask", never "allow" (fail closed).
"""

from __future__ import annotations

import os
import re
import shlex
import sys
from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from guard_common import SECRET_PATH_RE, audit, fingerprint, pre_tool_decision, read_event  # noqa: E402

SEPARATORS = {";", "&&", "||", "|", "&", "|&", "(", ")", "{", "}", "!", "\n"}
REDIRECTS = {">", ">>", "<", "<<", "<<<", ">&", "<&", "&>", "&>>", ">|", "2>", "2>>"}
KEYWORDS = {"if", "then", "else", "elif", "fi", "do", "done", "while", "until", "for", "case", "esac", "in", "time", "coproc"}
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish", "ash", "csh", "tcsh"}
INTERPRETERS = {"python", "pypy", "node", "nodejs", "deno", "bun", "perl", "ruby", "php", "lua", "Rscript", "osascript"}
# Arbitrary network clients. Fetching code or data must go through approved,
# reviewed tooling (package managers, git) or be done by a human.
NETWORK_EGRESS = {
    "curl", "wget", "nc", "ncat", "netcat", "telnet", "socat", "ftp", "tftp", "sftp", "scp", "ssh",
    "aria2c", "axel", "http", "https", "xh", "lwp-request", "lynx", "w3m", "links", "httpie", "websocat",
}
PRIV_ESC = {"sudo", "doas", "su", "pkexec", "runas"}
SECRET_STORES = (
    (("aws", "secretsmanager", "get-secret-value"), "AWS Secrets Manager read"),
    (("aws", "ssm", "get-parameter"), "AWS SSM parameter read"),
    (("aws", "ssm", "get-parameters"), "AWS SSM parameter read"),
    (("aws", "sts", "get-session-token"), "AWS session token minting"),
    (("aws", "configure", "export-credentials"), "AWS credential export"),
    (("gcloud", "secrets", "versions", "access"), "GCP Secret Manager read"),
    (("gcloud", "auth", "print-access-token"), "GCP token minting"),
    (("az", "keyvault", "secret", "show"), "Azure Key Vault read"),
    (("vault", "kv", "get"), "HashiCorp Vault read"),
    (("vault", "read"), "HashiCorp Vault read"),
    (("op", "read"), "1Password read"),
    (("op", "item", "get"), "1Password read"),
    (("gh", "auth", "token"), "GitHub token print"),
)
PUBLISH = {
    ("npm", "publish"), ("pnpm", "publish"), ("yarn", "publish"), ("twine", "upload"),
    ("gem", "push"), ("cargo", "publish"), ("docker", "push"), ("podman", "push"), ("mvn", "deploy"),
    ("gradle", "publish"), ("poetry", "publish"), ("uv", "publish"), ("dotnet", "nuget", "push"), ("helm", "push"),
}
SECRET_VAR_RE = re.compile(r"\$\{?[A-Za-z_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY|PRIVATE_KEY|CREDENTIAL|ACCESS_KEY)[A-Za-z0-9_]*\}?", re.I)
INLINE_NET_RE = re.compile(
    r"urllib|requests\.|httpx|aiohttp|http\.client|socket\.|smtplib|ftplib|paramiko|fetch\(|XMLHttpRequest|axios|"
    r"\bnet\.|https?\.(?:get|request)|child_process|Net::HTTP|open-uri|LWP::|Invoke-WebRequest|curl_exec"
)
SAFE_SECRET_PATH_CMDS = {"ls", "stat", "test", "[", "git", "rm", "touch", "mkdir", "chmod", "realpath", "dirname", "basename", "file"}
RM_DANGEROUS_TARGETS = {
    "/", "/*", "~", "~/", "~/*", "$HOME", "$HOME/", "$HOME/*", "${HOME}", "${HOME}/", ".", "./", "./*", "*", ".*",
    "..", "../", "/home", "/usr", "/etc", "/var", "/opt", "/bin", "/lib", "/boot", "/root", "/System", "/Users", "C:\\",
}


@dataclass
class Verdict:
    deny: List[str] = field(default_factory=list)
    ask: List[str] = field(default_factory=list)
    rules: List[str] = field(default_factory=list)

    def add(self, level: str, rule: str, reason: str) -> None:
        (self.deny if level == "deny" else self.ask).append(reason)
        self.rules.append(rule)

    def merge(self, other: "Verdict") -> None:
        self.deny += other.deny
        self.ask += other.ask
        self.rules += other.rules


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #


def tokenize(command: str) -> List[str]:
    lex = shlex.shlex(command.replace("\r", "\n"), posix=True, punctuation_chars=";&|(){}<>!")
    lex.whitespace = " \t"  # keep newlines as separators
    lex.whitespace_split = True
    lex.commenters = ""
    tokens: List[str] = []
    for tok in lex:
        # shlex groups adjacent punctuation, e.g. ")|" or ";;"; split runs we care about.
        if tok and set(tok) <= set(";&|(){}<>!") and tok not in SEPARATORS | REDIRECTS:
            tokens.extend(_split_punct(tok))
        else:
            tokens.append(tok)
    return tokens


def _split_punct(tok: str) -> List[str]:
    out, i = [], 0
    ordered = sorted(SEPARATORS | REDIRECTS, key=len, reverse=True)
    while i < len(tok):
        for cand in ordered:
            if tok.startswith(cand, i):
                out.append(cand)
                i += len(cand)
                break
        else:
            out.append(tok[i])
            i += 1
    return out


def segments(tokens: Sequence[str]) -> List[Tuple[Optional[str], List[str]]]:
    """Split into (preceding_separator, argv) with redirections removed."""
    out: List[Tuple[Optional[str], List[str]]] = []
    current: List[str] = []
    prev_sep: Optional[str] = None
    skip_next = False
    for tok in tokens:
        if skip_next:
            skip_next = False
            current.append(f"__redirect_target__:{tok}")
            continue
        if tok in SEPARATORS or tok == "\n":
            if current:
                out.append((prev_sep, current))
            current, prev_sep = [], tok
            continue
        if tok in REDIRECTS:
            skip_next = True
            continue
        current.append(tok)
    if current:
        out.append((prev_sep, current))
    return out


def strip_wrappers(argv: List[str]) -> List[str]:
    """Drop env assignments, keywords and exec wrappers to reach the real program."""
    args = [a for a in argv if not a.startswith("__redirect_target__:")]
    while args:
        head = args[0]
        name = os.path.basename(head)
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", head) or head in KEYWORDS:
            args = args[1:]
        elif name in {"env"} and len(args) > 1:
            args = args[1:]
            while args and (args[0].startswith("-") or "=" in args[0]):
                if args[0] in {"-u", "--unset", "-C", "--chdir", "-S", "--split-string"} and len(args) > 1:
                    args = args[2:]
                else:
                    args = args[1:]
        elif name in {"command", "builtin", "exec", "nohup", "noglob", "nocorrect", "setsid", "chronic", "unbuffer"}:
            args = [a for a in args[1:]]
            while args and args[0].startswith("-"):
                args = args[1:]
        elif name in {"time", "nice", "ionice", "stdbuf", "timeout", "watch", "flock", "xargs", "caffeinate"}:
            args = args[1:]
            # skip flags and their values, plus a leading duration for timeout
            while args and (args[0].startswith("-") or (name in {"timeout", "nice"} and re.match(r"^[\d.]+[smhd]?$", args[0]))):
                takes_value = name in {"nice", "ionice", "watch", "xargs", "flock", "timeout"} and args[0] in {"-n", "-c", "-d", "-I", "-L", "-P", "-s", "-k", "--signal", "-w"}
                args = args[2:] if takes_value and len(args) > 1 else args[1:]
        else:
            break
    return args


# --------------------------------------------------------------------------- #
# Rules
# --------------------------------------------------------------------------- #


def _invokes(argv: Sequence[str], words: Sequence[str]) -> bool:
    """True if argv runs words[0] and contains words[1:] in order (global flags may sit between)."""
    if not argv or os.path.basename(argv[0]) != words[0]:
        return False
    rest = iter(a for a in argv[1:] if not a.startswith("-"))
    return all(any(a == w for a in rest) for w in words[1:])


def git_subcommand(args: List[str]) -> Tuple[Optional[str], List[str]]:
    i = 1
    while i < len(args):
        a = args[i]
        if a in {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path"}:
            i += 2
        elif a.startswith("-"):
            i += 1
        else:
            return a, args[i + 1 :]
    return None, []


def check_segment(prev_sep: Optional[str], raw_argv: List[str], prev_argv: List[str], depth: int) -> Verdict:
    v = Verdict()
    argv = strip_wrappers(raw_argv)
    if not argv:
        return v
    cmd = os.path.basename(argv[0]).lstrip("`")
    if cmd.endswith(".exe"):
        cmd = cmd[:-4]
    if re.match(r"^(?:python|pypy|node|perl|ruby|php)[\d.]*$", cmd):
        cmd = re.sub(r"[\d.]+$", "", cmd) or cmd
    args = argv[1:]
    joined = " ".join(argv)

    if cmd in PRIV_ESC or any(os.path.basename(a) in PRIV_ESC for a in raw_argv[:3]):
        v.add("deny", "privilege_escalation", "privilege escalation (sudo/su/doas) is not permitted for the AI agent")

    if cmd in NETWORK_EGRESS:
        v.add("deny", "network_egress", f"`{cmd}` performs arbitrary network requests; use approved tooling or ask a human to run it")
    if cmd == "rsync" and any(re.match(r"^[^/\s]*[^/\s:]:", a) or "::" in a or a.startswith("rsync://") for a in args):
        v.add("deny", "network_egress", "remote rsync transfer")
    if cmd in {"powershell", "pwsh"} and re.search(r"(?i)-e(?:nc|ncodedcommand)?\b|invoke-webrequest|\biwr\b|invoke-restmethod|\birm\b|downloadstring|net\.webclient", joined):
        v.add("deny", "network_egress", "PowerShell download/encoded command")

    # `... | sh`, `base64 -d | bash`
    if prev_sep in {"|", "|&"} and (cmd in SHELLS or cmd in INTERPRETERS) and not any(not a.startswith("-") for a in args):
        prev = strip_wrappers(prev_argv)
        prev_cmd = os.path.basename(prev[0]) if prev else ""
        if prev_cmd in {"base64", "xxd", "openssl"} or prev_cmd in NETWORK_EGRESS:
            v.add("deny", "pipe_to_shell", "decoded or downloaded content piped into an interpreter")
        else:
            v.add("ask", "pipe_to_shell", "content piped into a shell/interpreter")

    # Recurse into `bash -c '...'`, `eval ...`
    if depth < 3:
        inner = None
        if cmd in SHELLS:
            for i, a in enumerate(args):
                if re.match(r"^-[a-zA-Z]*c[a-zA-Z]*$", a) and i + 1 < len(args):
                    inner = args[i + 1]
                    break
        elif cmd == "eval":
            inner = " ".join(args)
        if inner:
            v.merge(analyze(inner, depth + 1))

    if cmd in INTERPRETERS:
        for i, a in enumerate(args):
            if a in {"-c", "-e", "-E", "-r", "--eval", "-p", "--print"} and i + 1 < len(args) and INLINE_NET_RE.search(args[i + 1]):
                v.add("ask", "inline_network_code", f"inline {cmd} code performs network I/O")
                break
        if len(args) >= 2 and args[0] == "-m" and args[1] in {"http.server", "SimpleHTTPServer", "smtpd"}:
            v.add("ask", "inline_network_code", f"`{cmd} -m {args[1]}` opens a network service")

    # Secrets: files, env dumps, secret stores
    if cmd not in SAFE_SECRET_PATH_CMDS:
        for a in args + [t.split(":", 1)[1] for t in raw_argv if t.startswith("__redirect_target__:")]:
            target = a.split("=", 1)[-1] if a.startswith("--") else a
            if SECRET_PATH_RE.search(target.replace("~", "/home")):
                v.add("deny", "secret_file_access", f"access to secret material `{os.path.basename(target)}` is blocked; reference it via env vars or a secret manager")
                break
    if cmd in {"source", "."} and args and SECRET_PATH_RE.search(args[0]):
        v.add("deny", "secret_file_access", "sourcing a secrets file into the agent shell")
    if cmd == "printenv" or (cmd == "env" and not args) or (cmd == "export" and args[:1] == ["-p"]) or (cmd in {"set", "declare", "typeset"} and (not args or args[0] in {"-p", "-x"})):
        v.add("deny", "env_dump", "dumping the environment can expose credentials")
    if cmd in {"echo", "printf", "cat", "tee"} and SECRET_VAR_RE.search(joined):
        v.add("deny", "secret_echo", "printing a secret-named environment variable")
    for prefix, label in SECRET_STORES:
        if _invokes(argv, prefix):
            v.add("deny", "secret_store_read", f"{label} would place secret values in the AI context")
    if cmd == "kubectl" and "secret" in " ".join(args) and re.search(r"-o\s*(?:yaml|json|jsonpath)|--output", joined):
        v.add("deny", "secret_store_read", "Kubernetes Secret dump")

    # Destructive filesystem / disk
    if cmd == "rm":
        flags = "".join(a.lstrip("-") for a in args if a.startswith("-") and not a.startswith("--"))
        long_flags = {a for a in args if a.startswith("--")}
        recursive = "r" in flags.lower() or "--recursive" in long_flags
        force = "f" in flags or "--force" in long_flags
        targets = [a for a in args if not a.startswith("-")]
        if recursive and (force or "--no-preserve-root" in long_flags) and any(t.rstrip() in RM_DANGEROUS_TARGETS for t in targets):
            v.add("deny", "destructive_rm", "recursive force-delete of a root, home or whole-workspace path")
    if cmd in {"mkfs", "wipefs", "fdisk", "parted", "diskutil", "shred"} or cmd.startswith("mkfs."):
        v.add("deny", "destructive_disk", f"`{cmd}` can destroy disks")
    if cmd == "dd" and any(a.startswith("of=/dev/") for a in args):
        v.add("deny", "destructive_disk", "dd onto a block device")
    if cmd == "chmod" and any(re.match(r"^0?777$|^a\+rwx$", a) for a in args):
        v.add("ask", "insecure_permissions", "world-writable permissions")
    if cmd in {"crontab", "systemctl", "launchctl", "service"} and args and args[0] not in {"-l", "status", "list", "show", "is-active"}:
        v.add("ask", "persistence", f"`{cmd} {args[0]}` changes system services or scheduled jobs")
    if cmd == "history" and "-c" in args or (cmd == "unset" and "HISTFILE" in args):
        v.add("ask", "anti_forensics", "clearing shell history")

    # Git: history rewrites, guardrail bypass, hook tampering
    if cmd == "git":
        sub, rest = git_subcommand(argv)
        if "--no-verify" in rest or (sub == "commit" and "-n" in rest):
            v.add("deny", "guardrail_bypass", "`--no-verify` skips the pre-commit security hooks")
        if sub == "push":
            if any(a in {"-f", "--force", "--mirror", "--delete", "-d", "--prune"} or (a.startswith("+") and len(a) > 1) for a in rest):
                v.add("deny", "git_force_push", "force/mirror/delete pushes rewrite shared history")
            elif any(a.startswith("--force-with-lease") or a.startswith("--force-if-includes") for a in rest):
                v.add("ask", "git_force_push", "force-with-lease push")
        if sub in {"filter-branch", "filter-repo", "replace", "update-ref"}:
            v.add("ask", "git_history_rewrite", f"`git {sub}` rewrites history")
        if (sub == "reset" and "--hard" in rest) or (sub == "clean" and any(re.match(r"^-[a-zA-Z]*f", a) for a in rest)) or (sub == "branch" and "-D" in rest):
            v.add("ask", "git_destructive", f"`git {sub}` discards work")
        if sub == "config" and re.search(r"core\.hooksPath|core\.fsmonitor|core\.sshCommand|credential\.helper|--global|--system|url\..*\.insteadOf", " ".join(rest)):
            v.add("ask", "git_config_tamper", "git config change affecting hooks, credentials or global state")

    # Infrastructure: changes ship through reviewed CI, not from an agent shell
    if cmd in {"terraform", "tofu", "terragrunt"}:
        sub = next((a for a in args if not a.startswith("-")), "")
        if sub in {"apply", "destroy", "import", "taint", "untaint", "force-unlock", "run-all"} or "-auto-approve" in args or (sub == "state" and set(args) & {"rm", "mv", "push", "replace-provider"}):
            v.add("deny", "iac_apply", f"`{cmd} {sub}` mutates real infrastructure; run it through the reviewed CI pipeline")
        elif sub == "workspace" and set(args) & {"delete", "new"}:
            v.add("ask", "iac_change", f"`{cmd} workspace` change")
    if cmd == "pulumi" and set(args) & {"up", "update", "destroy", "refresh", "import", "cancel"}:
        v.add("deny", "iac_apply", "pulumi stack mutation; run it through CI")
    if cmd == "cdk" and set(args) & {"deploy", "destroy"}:
        v.add("deny", "iac_apply", "CDK deploy/destroy; run it through CI")
    if cmd in {"kubectl", "oc"}:
        sub = next((a for a in args if not a.startswith("-")), "")
        if sub in {"delete", "drain", "cordon", "taint", "replace"}:
            v.add("deny", "k8s_mutation", f"`{cmd} {sub}` against a cluster")
        elif sub in {"apply", "create", "edit", "patch", "scale", "rollout", "exec", "cp", "port-forward", "set", "label", "annotate", "debug"}:
            v.add("ask", "k8s_mutation", f"`{cmd} {sub}` against a cluster")
    if cmd == "helm" and set(args) & {"install", "upgrade", "uninstall", "delete", "rollback"}:
        v.add("ask", "k8s_mutation", "helm release change")
    if cmd == "aws" and "s3" in args and ("rb" in args or ("rm" in args and "--recursive" in args)):
        v.add("ask", "cloud_mutation", "aws s3 bucket removal / recursive delete")
    if cmd in {"aws", "gcloud", "az"} and re.search(r"\b(?:delete|terminate|destroy|remove|purge|deregister|detach|revoke|put-bucket-policy|put-bucket-acl|set-iam-policy|add-iam-policy-binding|create-access-key|create-login-profile)", joined):
        v.add("ask", "cloud_mutation", f"{cmd} call that deletes resources or changes access control")
    if cmd == "docker" and args and (args[0] in {"login"} or ("run" in args[:2] and re.search(r"--privileged|-v\s*/:/|--volume[= ]/:|--pid[= ]host|--net(?:work)?[= ]host|/var/run/docker\.sock", joined))):
        v.add("deny", "container_escape", "privileged/host-mounted container or registry login")

    for prefix in PUBLISH:
        if _invokes(argv, prefix):
            v.add("deny", "package_publish", f"`{' '.join(prefix)}` publishes artifacts (supply-chain risk); release through CI")
    return v


def analyze(command: str, depth: int = 0) -> Verdict:
    v = Verdict()
    if re.search(r"/dev/(?:tcp|udp)/", command):
        v.add("deny", "network_egress", "raw /dev/tcp socket")
    # Command substitutions inside double quotes are a single shlex token; analyse them too.
    if depth < 3:
        for inner in re.findall(r"\$\(([^()]*)\)|`([^`]*)`", command):
            text = inner[0] or inner[1]
            if text.strip():
                v.merge(analyze(text, depth + 1))
    try:
        tokens = tokenize(command)
    except ValueError:
        # Unbalanced quotes etc. Be conservative.
        if re.search(r"(?<![\w-])(?:%s)(?![\w-])" % "|".join(map(re.escape, sorted(NETWORK_EGRESS))), command):
            v.add("deny", "network_egress", "unparseable command referencing a network client")
        else:
            v.add("ask", "unparseable", "command could not be parsed safely")
        return v
    prev_argv: List[str] = []
    for prev_sep, argv in segments(tokens):
        v.merge(check_segment(prev_sep, argv, prev_argv, depth))
        prev_argv = argv
    return v


def main() -> None:
    event = read_event()
    if event.get("tool_name") not in {"Bash", "Monitor"}:
        return
    command = (event.get("tool_input") or {}).get("command") or ""
    if not command.strip():
        return
    verdict = analyze(command)
    if verdict.deny:
        audit("bash_guard", event, "deny", verdict.rules, {"command_fp": fingerprint(command)})
        pre_tool_decision("deny", "; ".join(dict.fromkeys(verdict.deny)) + ". See docs/claude-guardrails.md#4-tooling-controls")
    if verdict.ask:
        audit("bash_guard", event, "ask", verdict.rules, {"command_fp": fingerprint(command)})
        pre_tool_decision("ask", "; ".join(dict.fromkeys(verdict.ask)))


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:  # fail closed: a crashing guard must not silently allow
        pre_tool_decision("ask", f"bash_guard error ({type(exc).__name__}); manual review required")
