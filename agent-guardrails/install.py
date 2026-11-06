#!/usr/bin/env python3
"""Install the agent guardrails into a project for Claude Code, Cursor or GitHub Copilot.

    python3 install.py --target cursor  --project /path/to/repo
    python3 install.py --target copilot --project /path/to/repo
    python3 install.py --target claude  --project /path/to/repo
    python3 install.py --target all     --project /path/to/repo --dry-run

What it does:
  1. Copies the runtime (hook.py, guardrails_core/, adapters/) to <project>/.agent-guardrails/
  2. Copies the skill to the host's skill folder
  3. Adds the host's hook configuration, merging with what is already there

It only ever adds restrictive settings (hooks, deny and ask rules, the bypass
lock, the sandbox when none is set). It never adds allow rules and never removes
anything. Claude Code users can install the plugin instead: see README.md.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, List

HERE = Path(__file__).resolve().parent
RUNTIME = ["hook.py", "guardrails_core", "adapters"]
SKILL = HERE / "skills" / "agent-guardrails"
SKILL_DIRS = {"claude": ".claude/skills", "cursor": ".cursor/skills", "copilot": ".github/skills"}


class Plan:
    def __init__(self, project: Path, dry_run: bool) -> None:
        self.project = project
        self.dry_run = dry_run
        self.changes: List[str] = []

    def check_dest(self, dest: Path) -> None:
        """Refuse to write through a symlink or outside the project (a hostile clone
        could point a destination at a file elsewhere on the machine)."""
        rel = dest.relative_to(self.project)
        current = self.project
        for part in rel.parts:
            current = current / part
            if current.is_symlink():
                raise SystemExit(f"error: {current} is a symlink; refusing to install through it")
        if not dest.resolve().is_relative_to(self.project.resolve()):
            raise SystemExit(f"error: {dest} resolves outside the project")

    def copy_tree(self, src: Path, dest: Path) -> None:
        self.check_dest(dest)
        self.changes.append(f"copy  {src.relative_to(HERE)} -> {dest.relative_to(self.project)}")
        if self.dry_run:
            return
        if src.is_dir():
            if dest.exists():
                shutil.rmtree(dest)
            shutil.copytree(src, dest, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        else:
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dest)

    def write_json(self, dest: Path, data: Dict[str, Any], verb: str) -> None:
        self.check_dest(dest)
        self.changes.append(f"{verb:5} {dest.relative_to(self.project)}")
        if self.dry_run:
            return
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SystemExit(f"error: {path} is not a JSON object; fix it before installing")
    return data


def template(*parts: str) -> Dict[str, Any]:
    return json.loads((HERE / "templates" / Path(*parts)).read_text(encoding="utf-8"))


def union(existing: List[Any], extra: List[Any]) -> List[Any]:
    return existing + [item for item in extra if item not in existing]


def install_runtime(plan: Plan) -> None:
    target = plan.project / ".agent-guardrails"
    for name in RUNTIME:
        plan.copy_tree(HERE / name, target / name)


def install_skill(plan: Plan, host: str) -> None:
    plan.copy_tree(SKILL, plan.project / SKILL_DIRS[host] / "agent-guardrails")


def install_claude(plan: Plan) -> None:
    path = plan.project / ".claude" / "settings.json"
    settings = load_json(path)
    tpl = template("claude-code", "settings.json")
    perms = settings.setdefault("permissions", {})
    for key in ("ask", "deny"):
        perms[key] = union(perms.get(key, []), tpl["permissions"][key])
    perms["disableBypassPermissionsMode"] = "disable"
    if "sandbox" not in settings:
        settings["sandbox"] = tpl["sandbox"]
    hooks = settings.setdefault("hooks", {})
    for event, groups in tpl["hooks"].items():
        current = hooks.setdefault(event, [])
        for group in groups:
            if group not in current:
                current.append(group)
    plan.write_json(path, settings, "merge" if path.exists() else "write")


def install_cursor(plan: Plan) -> None:
    path = plan.project / ".cursor" / "hooks.json"
    config = load_json(path) or {"version": 1, "hooks": {}}
    config.setdefault("version", 1)
    hooks = config.setdefault("hooks", {})
    for event, entries in template("cursor", "hooks.json")["hooks"].items():
        current = hooks.setdefault(event, [])
        for entry in entries:
            same_command = [e for e in current if isinstance(e, dict) and e.get("command") == entry["command"]]
            if entry in same_command:
                continue
            for stale in same_command:  # a weakened copy (other matcher, no failClosed): replace it
                plan.changes.append(f"fix   .cursor/hooks.json {event}: replaced a modified agent-guardrails entry")
                current.remove(stale)
            current.append(entry)
    plan.write_json(path, config, "merge" if path.exists() else "write")


def install_copilot(plan: Plan) -> None:
    path = plan.project / ".github" / "hooks" / "agent-guardrails.json"
    plan.write_json(path, template("copilot", "agent-guardrails.json"), "write")


INSTALLERS = {"claude": install_claude, "cursor": install_cursor, "copilot": install_copilot}


def main(argv: List[str] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", required=True, choices=[*INSTALLERS, "all"])
    parser.add_argument("--project", default=".", help="project root (default: current directory)")
    parser.add_argument("--dry-run", action="store_true", help="show the changes without making them")
    args = parser.parse_args(argv)

    project = Path(args.project).resolve()
    if not project.is_dir():
        parser.error(f"{project} is not a directory")
    if project == HERE or HERE in project.parents:
        parser.error("install into a project, not into the agent-guardrails source folder")

    hosts = list(INSTALLERS) if args.target == "all" else [args.target]

    def apply(dry_run: bool) -> Plan:
        plan = Plan(project, dry_run)
        install_runtime(plan)
        for host in hosts:
            install_skill(plan, host)
            INSTALLERS[host](plan)
        return plan

    # Check every destination first, so an unsafe one stops the install before anything is written.
    plan = apply(dry_run=True)
    if not args.dry_run:
        plan = apply(dry_run=False)

    print(("Planned changes" if args.dry_run else "Installed") + f" in {project}:")
    for change in plan.changes:
        print(f"  {change}")
    if not args.dry_run:
        print("\nNext: commit these files, then open the project in your tool and trust the workspace.")
        print("Audit log: .agent-guardrails/audit/guardrail-events.jsonl (ignored by git).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
