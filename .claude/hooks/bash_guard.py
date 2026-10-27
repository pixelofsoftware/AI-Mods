#!/usr/bin/env python3
"""PreToolUse hook for the Bash tool.

Permission rules match command *text*, so `Bash(curl *)` in deny does not stop
`/usr/bin/curl`, `bash -c 'curl ...'` or `$(curl ...)`. This hook parses the
command (lines, heredocs, pipelines, subshells, wrappers, `-c` strings) and returns:

  deny -> blocked outright (network egress, secret access, privilege escalation,
          irreversible infra changes, guardrail bypass)
  ask  -> needs explicit human approval even in acceptEdits/auto mode
  (no output) -> normal permission flow from .claude/settings.json

Anything it cannot analyse with confidence (dynamic command names, unparseable
quoting, nesting too deep, oversized input) becomes "ask". If the hook itself
fails it answers "ask", never "allow" (fail closed).
"""

from __future__ import annotations

import os
import re
import shlex
import sys
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Sequence, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from guard_common import GUARDRAIL_PATH_RE, SECRET_PATH_RE, audit, fingerprint, pre_tool_decision, read_event  # noqa: E402

MAX_DEPTH = 3
MAX_COMMAND_CHARS = 100_000
REDIR = "\x00R"  # marker prefix for redirection targets kept inside an argv

SEPARATORS = {";", "&&", "||", "|", "&", "|&", "(", ")", "{", "}", "!"}
REDIRECTS = {">", ">>", "<", "<<", "<<-", "<<<", ">&", "<&", "&>", "&>>", ">|", "2>", "2>>"}
WRITE_REDIRECTS = {">", ">>", ">|", "&>", "&>>", "2>", "2>>"}
KEYWORDS = {"if", "then", "else", "elif", "fi", "do", "done", "while", "until", "for", "case", "esac", "in", "time", "coproc"}
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish", "ash", "csh", "tcsh", "busybox"}
INTERPRETERS = {"python", "pypy", "node", "nodejs", "deno", "bun", "perl", "ruby", "php", "lua", "Rscript", "osascript"}
# Arbitrary network clients. Fetching code or data must go through approved,
# reviewed tooling (package managers, git) or be done by a human.
NETWORK_EGRESS = {
    "curl", "wget", "nc", "ncat", "netcat", "telnet", "socat", "ftp", "tftp", "sftp", "scp", "ssh",
    "aria2c", "axel", "http", "https", "xh", "lwp-request", "lynx", "w3m", "links", "httpie", "websocat",
}
DNS_TOOLS = {"dig", "nslookup", "host", "drill"}
NETWORK_WORD_RE = re.compile(r"(?<![\w-])(?:%s)(?![\w-])" % "|".join(sorted(map(re.escape, NETWORK_EGRESS), key=len, reverse=True)))
PRIV_ESC = {"sudo", "doas", "su", "pkexec", "runas"}
EXEC_WRAPPERS = {"command", "builtin", "exec", "nohup", "noglob", "nocorrect", "setsid", "chronic", "unbuffer", "toybox"}
TIMING_WRAPPERS = {"time", "nice", "ionice", "stdbuf", "timeout", "watch", "flock", "xargs", "caffeinate", "parallel"}
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
PUBLISH = (
    ("npm", "publish"), ("pnpm", "publish"), ("yarn", "publish"), ("twine", "upload"),
    ("gem", "push"), ("cargo", "publish"), ("docker", "push"), ("podman", "push"), ("mvn", "deploy"),
    ("gradle", "publish"), ("poetry", "publish"), ("uv", "publish"), ("dotnet", "nuget", "push"), ("helm", "push"),
)
SECRET_VAR_RE = re.compile(r"\$\{?[A-Za-z_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY|PRIVATE_KEY|CREDENTIAL|ACCESS_KEY)[A-Za-z0-9_]*\}?", re.I)
SECRET_WORD_RE = re.compile(r"(?i)secret|token|passw|api_?key|private_?key|credential")
INLINE_NET_RE = re.compile(
    r"urllib|requests\.|httpx|aiohttp|http\.client|socket\.|smtplib|ftplib|paramiko|fetch\(|XMLHttpRequest|axios|"
    r"\bnet\.|https?\.(?:get|request)|child_process|Net::HTTP|open-uri|LWP::|Invoke-WebRequest|curl_exec"
)
ENV_GLOB_RE = re.compile(r"(?:^|/)\.env[^/]*[*?\[]")
HEREDOC_RE = re.compile(r"(?<!<)<<(-?)\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\2")
# Commands that only look at a path's metadata, or remove/ignore it.
SAFE_SECRET_PATH_CMDS = {"ls", "stat", "test", "[", "rm", "touch", "mkdir", "chmod", "realpath", "dirname", "basename", "file"}
GIT_SAFE_SECRET_SUBCOMMANDS = {"rm", "ls-files", "check-ignore", "status"}
RM_DANGEROUS_TARGETS = {
    "/", "/*", "~", "~/", "~/*", "$HOME", "$HOME/", "$HOME/*", "${HOME}", "${HOME}/", ".", "./", "./*", "*", ".*",
    "..", "../", "/home", "/usr", "/etc", "/var", "/opt", "/bin", "/lib", "/boot", "/root", "/System", "/Users", "C:\\",
}
KUBECTL_VALUE_FLAGS = {"-n", "--namespace", "--context", "--cluster", "--kubeconfig", "-o", "--output", "-l", "--selector", "-s", "--server", "--user", "--as", "-f", "--filename"}


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


def logical_lines(command: str) -> List[Tuple[str, List[Tuple[str, bool]]]]:
    """Split on unquoted newlines; return each line with the heredoc bodies it opens.

    Each body comes with `expands`: True for `<<EOF` (the shell expands $(...) in it),
    False for `<<'EOF'` (literal data).

    Heredoc bodies are taken verbatim (no quote tracking) so an apostrophe in a
    heredoc cannot glue later lines together.
    """
    text = command.replace("\r\n", "\n").replace("\r", "\n")
    n = len(text)
    pos = 0
    result: List[Tuple[str, List[Tuple[str, bool]]]] = []
    while pos <= n:
        buf: List[str] = []
        quote: Optional[str] = None
        ended = True
        while pos < n:
            ch = text[pos]
            if ch == "\\" and quote != "'" and pos + 1 < n:
                if text[pos + 1] == "\n" and quote is None:  # line continuation
                    pos += 2
                    continue
                buf.append(text[pos : pos + 2])
                pos += 2
                continue
            if ch in "'\"":
                if quote is None:
                    quote = ch
                elif quote == ch:
                    quote = None
            if ch == "\n" and quote is None:
                pos += 1
                ended = False
                break
            buf.append(ch)
            pos += 1
        if ended:
            pos = n + 1
        line = "".join(buf)
        bodies: List[Tuple[str, bool]] = []
        for m in HEREDOC_RE.finditer(line):
            body: List[str] = []
            while pos < n:
                nl = text.find("\n", pos)
                nl = n if nl == -1 else nl
                raw = text[pos:nl]
                pos = nl + 1
                if (raw.lstrip("\t") if m.group(1) else raw) == m.group(3):
                    break
                body.append(raw)
            bodies.append(("\n".join(body), not m.group(2)))
        result.append((line, bodies))
    return result


def tokenize(line: str) -> List[str]:
    lex = shlex.shlex(line, posix=True, punctuation_chars=";&|(){}<>!")
    lex.whitespace = " \t\n"
    lex.whitespace_split = True
    lex.commenters = ""
    tokens: List[str] = []
    for tok in lex:
        # shlex groups adjacent punctuation, e.g. ")|" or ";;"; split runs we care about.
        if tok and set(tok) <= set(";&|(){}<>!") and tok not in SEPARATORS | REDIRECTS and tok != "{}":
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
    """Split into (preceding_separator, argv). Redirections become REDIR markers."""
    out: List[Tuple[Optional[str], List[str]]] = []
    current: List[str] = []
    prev_sep: Optional[str] = None
    pending_op: Optional[str] = None
    for tok in tokens:
        if pending_op is not None:
            current.append(f"{REDIR}{pending_op}\x00{tok}")
            pending_op = None
            continue
        if tok in SEPARATORS:
            if current:
                out.append((prev_sep, current))
            current, prev_sep = [], tok
            continue
        if tok in REDIRECTS:
            pending_op = tok
            continue
        current.append(tok)
    if current:
        out.append((prev_sep, current))
    return out


def redirections(argv: Iterable[str]) -> List[Tuple[str, str]]:
    return [tuple(a[len(REDIR):].split("\x00", 1)) for a in argv if a.startswith(REDIR)]  # type: ignore[misc]


def strip_wrappers(argv: List[str]) -> List[str]:
    """Drop env assignments, keywords and exec wrappers to reach the real program."""
    args = [a for a in argv if not a.startswith(REDIR)]
    while args:
        head = args[0]
        name = os.path.basename(head)
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", head) or head in KEYWORDS:
            args = args[1:]
        elif name == "env":
            rest = args[1:]
            while rest and (rest[0].startswith("-") or "=" in rest[0]):
                takes_value = rest[0] in {"-u", "--unset", "-C", "--chdir", "-S", "--split-string"}
                rest = rest[2:] if takes_value and len(rest) > 1 else rest[1:]
            if not rest:
                return ["env"]  # `env`, `env -0`, `env -u X`: prints the environment
            args = rest
        elif name in EXEC_WRAPPERS:
            args = args[1:]
            while args and args[0].startswith("-"):
                args = args[1:]
        elif name in TIMING_WRAPPERS:
            args = args[1:]
            while args and (args[0].startswith("-") or (name in {"timeout", "nice"} and re.match(r"^[\d.]+[smhd]?$", args[0]))):
                takes_value = args[0] in {"-n", "-c", "-d", "-I", "-L", "-P", "-s", "-k", "--signal", "-w", "-j"}
                args = args[2:] if takes_value and len(args) > 1 else args[1:]
        elif name == "busybox" and len(args) > 1 and not args[1].startswith("-"):
            args = args[1:]
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


def _first_positional(args: Sequence[str], value_flags: Iterable[str] = ()) -> Tuple[str, List[str]]:
    value_flags = set(value_flags)
    i = 0
    while i < len(args):
        a = args[i]
        if a in value_flags:
            i += 2
        elif a.startswith("-"):
            i += 1
        else:
            return a, list(args[i + 1 :])
    return "", []


def git_parse(argv: List[str]) -> Tuple[Optional[str], List[str], List[str]]:
    """Return (subcommand, rest, `-c` config values)."""
    configs: List[str] = []
    i = 1
    while i < len(argv):
        a = argv[i]
        if a == "-c" and i + 1 < len(argv):
            configs.append(argv[i + 1])
            i += 2
        elif a in {"-C", "--git-dir", "--work-tree", "--namespace", "--exec-path"}:
            i += 2
        elif a.startswith("-"):
            i += 1
        else:
            return a, argv[i + 1 :], configs
    return None, [], configs


def _path_candidates(arg: str) -> List[str]:
    out = [arg]
    if ":" in arg:
        out.append(arg.split(":", 1)[1])  # git show HEAD:.env, scp host:path
    if "=" in arg:
        out.append(arg.split("=", 1)[1])  # --file=.env
    return out


def _secret_reference(args: Iterable[str]) -> Optional[str]:
    for a in args:
        for cand in _path_candidates(a):
            if SECRET_PATH_RE.search(cand.replace("~", "/home")) or ENV_GLOB_RE.search(cand):
                return cand
    return None


def check_segment(prev_sep: Optional[str], raw_argv: List[str], prev_argv: List[str], depth: int, raw_command: str) -> Verdict:
    v = Verdict()
    argv = strip_wrappers(raw_argv)
    redirs = redirections(raw_argv)
    if not argv:
        # Bare redirection such as `> .claude/settings.local.json`
        for op, target in redirs:
            if op in WRITE_REDIRECTS and GUARDRAIL_PATH_RE.search(target):
                v.add("ask", "guardrail_change", f"shell write to AI guardrail file `{target}` needs security review")
            if op in WRITE_REDIRECTS | {"<"} and _secret_reference([target]):
                v.add("deny", "secret_file_access", f"redirection touching secret material `{os.path.basename(target)}`")
        return v
    head = argv[0]
    cmd = os.path.basename(head)
    if cmd.endswith(".exe"):
        cmd = cmd[:-4]
    if re.match(r"^(?:python|pypy|node|perl|ruby|php)[\d.]*$", cmd):
        cmd = re.sub(r"[\d.]+$", "", cmd) or cmd
    args = argv[1:]
    joined = " ".join(argv)

    # Command name decided at runtime: `$c url`, `$(echo x) url`, `/usr/bin/cur? url`.
    if re.search(r"[$`*?\[]", head):
        if NETWORK_WORD_RE.search(raw_command):
            v.add("deny", "network_egress", "dynamic command name next to a network client")
        else:
            v.add("ask", "dynamic_command", "command name is computed at runtime and cannot be checked")

    if cmd in PRIV_ESC or any(os.path.basename(a) in PRIV_ESC for a in raw_argv[:3]):
        v.add("deny", "privilege_escalation", "privilege escalation (sudo/su/doas) is not permitted for the AI agent")

    if cmd in NETWORK_EGRESS:
        v.add("deny", "network_egress", f"`{cmd}` performs arbitrary network requests; use approved tooling or ask a human to run it")
    if cmd == "rsync" and any(re.match(r"^[^/\s]*[^/\s:]:", a) or "::" in a or a.startswith("rsync://") for a in args):
        v.add("deny", "network_egress", "remote rsync transfer")
    if cmd == "openssl" and args[:1] and args[0] in {"s_client", "s_server"}:
        v.add("deny", "network_egress", "raw TLS connection via openssl")
    if cmd in DNS_TOOLS:
        v.add("ask", "dns_query", f"`{cmd}` can exfiltrate data through DNS")
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

    # Inner command strings: `bash -c '...'`, `script -c`, `eval`, `bash <<< '...'`, `find -exec`
    inner: List[str] = []
    if cmd in SHELLS or cmd == "script":
        for i, a in enumerate(args):
            if re.match(r"^-[a-zA-Z]*c[a-zA-Z]*$", a):
                j = i + 1
                if j < len(args) and args[j] == "--":
                    j += 1
                if j < len(args):
                    inner.append(args[j])
                break
        inner += [target for op, target in redirs if op == "<<<"]
    elif cmd == "eval":
        inner.append(" ".join(args))
    elif cmd in INTERPRETERS:
        for i, a in enumerate(args):
            if a in {"-c", "-e", "-E", "-r", "--eval", "-p", "--print"} and i + 1 < len(args) and INLINE_NET_RE.search(args[i + 1]):
                v.add("ask", "inline_network_code", f"inline {cmd} code performs network I/O")
                break
        if len(args) >= 2 and args[0] == "-m" and args[1] in {"http.server", "SimpleHTTPServer", "smtpd"}:
            v.add("ask", "inline_network_code", f"`{cmd} -m {args[1]}` opens a network service")
    if cmd == "find":
        sub: List[str] = []
        collecting = False
        for a in args:
            if a in {"-exec", "-execdir", "-ok", "-okdir"}:
                collecting, sub = True, []
                continue
            if collecting and a in {";", "\\;", "+"}:
                collecting = False
                if sub:
                    inner.append(" ".join(shlex.quote(x) for x in sub if x != "{}"))
                continue
            if collecting:
                sub.append(a)
        if collecting and sub:
            inner.append(" ".join(shlex.quote(x) for x in sub if x != "{}"))
    for text in inner:
        if depth + 1 >= MAX_DEPTH:
            v.add("ask", "nesting_limit", "command nesting too deep to analyse")
        else:
            v.merge(analyze(text, depth + 1))

    # Secrets: files, env dumps, secret stores
    write_targets = [t for op, t in redirs if op in WRITE_REDIRECTS]
    git_sub, git_rest, git_configs = git_parse(argv) if cmd == "git" else (None, [], [])
    secret_args = args + [t for op, t in redirs if op not in {"<<", "<<-", "<<<"}]
    check_secrets = cmd not in SAFE_SECRET_PATH_CMDS and not (cmd == "git" and git_sub in GIT_SAFE_SECRET_SUBCOMMANDS)
    hit = _secret_reference(secret_args) if check_secrets else None
    if hit:
        v.add("deny", "secret_file_access", f"access to secret material `{os.path.basename(hit) or hit}` is blocked; reference it via env vars or a secret manager")
    if cmd in {"source", "."} and args and _secret_reference(args[:1]):
        v.add("deny", "secret_file_access", "sourcing a secrets file into the agent shell")
    if (
        cmd == "printenv"
        or (cmd == "env" and not args)
        or (cmd == "export" and (not args or args[0] == "-p"))
        or (cmd == "set" and not args)
        or (cmd in {"declare", "typeset"} and (not args or any(a.startswith("-") and "p" in a for a in args)))
        or (cmd == "compgen" and "-v" in args)
    ):
        v.add("deny", "env_dump", "dumping the environment can expose credentials")
    if cmd in {"echo", "printf", "cat", "tee"} and SECRET_VAR_RE.search(joined):
        v.add("deny", "secret_echo", "printing a secret-named environment variable")
    if cmd in {"grep", "egrep", "fgrep"} and any(re.match(r"^-[a-zA-Z]*[rR]", a) or a in {"--recursive", "--dereference-recursive"} for a in args):
        pattern, _ = _first_positional(args, {"-e", "-f", "-m", "-A", "-B", "-C", "--include", "--exclude"})
        if SECRET_WORD_RE.search(pattern) or any(SECRET_WORD_RE.search(a) for a in args if a.startswith("-e")):
            v.add("ask", "secret_search", "recursive search for secret-like names may read .env and key files")
    for prefix, label in SECRET_STORES:
        if _invokes(argv, prefix):
            v.add("deny", "secret_store_read", f"{label} would place secret values in the AI context")
    if cmd == "kubectl" and re.search(r"\bsecrets?\b", joined) and re.search(r"(?:^|\s)(?:-o|--output)(?:\s|=)|(?:^|\s)-o(?:yaml|json|jsonpath|go-template)", joined):
        v.add("deny", "secret_store_read", "Kubernetes Secret dump")

    # Writes into the guardrails from the shell bypass file_guard's HITL check
    writes = list(write_targets)
    if cmd == "tee":
        writes += [a for a in args if not a.startswith("-")]
    if cmd in {"cp", "mv", "install", "ln", "rsync"} and len([a for a in args if not a.startswith("-")]) >= 2:
        writes.append([a for a in args if not a.startswith("-")][-1])
    if cmd in {"sed", "perl"} and any(a.startswith("-i") or a == "--in-place" for a in args):
        writes += [a for a in args if not a.startswith("-")][1:]
    if cmd == "dd":
        writes += [a[3:] for a in args if a.startswith("of=")]
    if cmd == "truncate":
        writes += [a for a in args if not a.startswith("-")]
    for target in writes:
        if GUARDRAIL_PATH_RE.search(target):
            v.add("ask", "guardrail_change", f"shell write to AI guardrail file `{target}` needs security review")
            break

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
    if (cmd == "history" and "-c" in args) or (cmd == "unset" and "HISTFILE" in args):
        v.add("ask", "anti_forensics", "clearing shell history")

    # Git: history rewrites, guardrail bypass, hook tampering, arbitrary writes
    if cmd == "git":
        env_prefix = [a for a in raw_argv if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", a)]
        if git_sub in {"commit", "push", "merge", "rebase", "am"} and any(re.match(r"^(?:SKIP|PRE_COMMIT_ALLOW_NO_CONFIG|HUSKY)=", a) for a in env_prefix):
            v.add("deny", "guardrail_bypass", "skipping pre-commit hooks via environment variable")
        if "--no-verify" in git_rest or (git_sub == "commit" and any(re.match(r"^-[a-zA-Z]*n[a-zA-Z]*$", a) for a in git_rest)):
            v.add("deny", "guardrail_bypass", "`--no-verify` skips the pre-commit security hooks")
        for conf in git_configs + (git_rest if git_sub == "config" else []):
            if re.search(r"(?i)core\.hookspath", conf):
                v.add("deny", "guardrail_bypass", "redirecting git hooks disables pre-commit checks")
            if re.search(r"(?i)^alias\.[^=]*=\s*!", conf) or (git_sub == "config" and conf.startswith("!")):
                level = "deny" if NETWORK_WORD_RE.search(conf) else "ask"
                v.add(level, "git_alias_exec", "git alias that runs a shell command")
        if any(a == "--output" or a.startswith("--output=") for a in git_rest):
            v.add("deny", "git_arbitrary_write", "`git --output` writes arbitrary content to arbitrary files")
        if git_sub == "push":
            short_bundles = [a for a in git_rest if re.match(r"^-[a-zA-Z]+$", a)]
            if (
                any(a in {"--force", "--mirror", "--delete", "--prune"} for a in git_rest)
                or any("f" in a or "d" in a for a in short_bundles)
                or any((a.startswith("+") or a.startswith(":")) and len(a) > 1 for a in git_rest)
            ):
                v.add("deny", "git_force_push", "force/mirror/delete pushes rewrite shared history")
            elif any(a.startswith("--force-with-lease") or a.startswith("--force-if-includes") for a in git_rest):
                v.add("ask", "git_force_push", "force-with-lease push")
        if git_sub in {"filter-branch", "filter-repo", "replace", "update-ref"}:
            v.add("ask", "git_history_rewrite", f"`git {git_sub}` rewrites history")
        if (git_sub == "reset" and "--hard" in git_rest) or (git_sub == "clean" and any(re.match(r"^-[a-zA-Z]*f", a) for a in git_rest)) or (git_sub == "branch" and "-D" in git_rest):
            v.add("ask", "git_destructive", f"`git {git_sub}` discards work")
        if git_sub == "config" and re.search(r"core\.fsmonitor|core\.sshCommand|credential\.helper|--global|--system|url\..*\.insteadOf", " ".join(git_rest)):
            v.add("ask", "git_config_tamper", "git config change affecting credentials or global state")

    # Infrastructure: changes ship through reviewed CI, not from an agent shell
    if cmd in {"terraform", "tofu", "terragrunt"}:
        sub, _ = _first_positional(args, {"-chdir"})
        if sub in {"apply", "destroy", "import", "taint", "untaint", "force-unlock", "run-all"} or "-auto-approve" in args or (sub == "state" and set(args) & {"rm", "mv", "push", "replace-provider"}):
            v.add("deny", "iac_apply", f"`{cmd} {sub}` mutates real infrastructure; run it through the reviewed CI pipeline")
        elif sub == "workspace" and set(args) & {"delete", "new"}:
            v.add("ask", "iac_change", f"`{cmd} workspace` change")
    if cmd == "pulumi" and set(args) & {"up", "update", "destroy", "refresh", "import", "cancel"}:
        v.add("deny", "iac_apply", "pulumi stack mutation; run it through CI")
    if cmd == "cdk" and set(args) & {"deploy", "destroy"}:
        v.add("deny", "iac_apply", "CDK deploy/destroy; run it through CI")
    if cmd in {"kubectl", "oc"}:
        sub, _ = _first_positional(args, KUBECTL_VALUE_FLAGS)
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


def _substitutions(text: str, depth: int) -> Verdict:
    """Analyse $(...) and `...` bodies, which run even inside double quotes."""
    v = Verdict()
    if re.search(r"/dev/(?:tcp|udp)/", text):
        v.add("deny", "network_egress", "raw /dev/tcp socket")
    for inner in re.findall(r"\$\(([^()]*)\)|`([^`]*)`", text):
        body = inner[0] or inner[1]
        if body.strip():
            if depth + 1 >= MAX_DEPTH:
                v.add("ask", "nesting_limit", "command nesting too deep to analyse")
            else:
                v.merge(analyze(body, depth + 1))
    return v


def analyze(command: str, depth: int = 0) -> Verdict:
    v = Verdict()
    if len(command) > MAX_COMMAND_CHARS:
        v.add("ask", "oversized", "command too large to analyse")
        return v
    for line, bodies in logical_lines(command):
        v.merge(_substitutions(line, depth))
        try:
            tokens = tokenize(line)
        except ValueError:
            # Unbalanced quotes etc. Be conservative.
            if NETWORK_WORD_RE.search(line):
                v.add("deny", "network_egress", "unparseable command referencing a network client")
            else:
                v.add("ask", "unparseable", "command could not be parsed safely")
            continue
        segs = segments(tokens)
        prev_argv: List[str] = []
        consumers = set()
        for prev_sep, argv in segs:
            v.merge(check_segment(prev_sep, argv, prev_argv, depth, line))
            prev_argv = argv
            stripped = strip_wrappers(argv)
            if stripped:
                consumers.add(re.sub(r"[\d.]+$", "", os.path.basename(stripped[0])))
        for body, expands in bodies:
            if consumers & (SHELLS | {"eval", "source", "."}):
                if depth + 1 >= MAX_DEPTH:
                    v.add("ask", "nesting_limit", "command nesting too deep to analyse")
                else:
                    v.merge(analyze(body, depth + 1))
                continue
            if expands:  # `cat <<EOF` still runs $(...) inside the body
                v.merge(_substitutions(body, depth))
            if consumers & INTERPRETERS and INLINE_NET_RE.search(body):
                v.add("ask", "inline_network_code", "heredoc script performs network I/O")
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
