#!/usr/bin/env python3
"""audit.py — read a Kortix project's kortix.yaml and report what each agent can reach.

An agentic enterprise is a company whose work runs through agents. Before that
work touches production, someone has to answer one question per agent: what can
this one reach, and what does it do without asking a person?

This script answers it from the manifest alone. It reads `kortix.yaml`, prints
one row per agent (mode, permission, and every grant), then lists the findings
that matter for a company that has to pass a security review.

Usage:
    python audit.py kortix.yaml
    python audit.py kortix.yaml --json
    python audit.py kortix.yaml --fail-on high

Exit codes: 0 clean, 1 findings at or above --fail-on (default: high),
2 the file is missing or is not valid YAML.

The checks follow the kortix.yaml schema at https://kortix.com/schema/kortix.schema.json
and the reference at https://kortix.com/docs/developers. Grants are
deny-by-default: an omitted `skills`, `subagents`, `commands`, `extensions`,
`connectors`, `secrets` or `kortix_permissions` grant is none. `tools` defaults
to `all` and `permission` defaults to `allow`, which is why those two are the
ones worth reading twice.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("PyYAML is required: pip install -r requirements.txt")

GRANTS = (
    "tools",
    "skills",
    "subagents",
    "commands",
    "extensions",
    "connectors",
    "secrets",
    "kortix_permissions",
    "apps",
)
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}


def _grant(value) -> str:
    """Render one grant the way the manifest means it."""
    if value is None:
        return "none"
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return ", ".join(str(v) for v in value) if value else "none"
    if isinstance(value, dict):
        if "exclude" in value:
            return "all except " + ", ".join(str(v) for v in value["exclude"])
        return json.dumps(value, sort_keys=True)
    return str(value)


def _permission(value) -> str:
    """`permission` is a string, or a per-tool map. Summarise the map."""
    if value is None:
        return "allow (default)"
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        asks = [k for k, v in value.items() if v == "ask"]
        denies = [k for k, v in value.items() if v == "deny"]
        parts = []
        if asks:
            parts.append("ask: " + ", ".join(sorted(asks)))
        if denies:
            parts.append("deny: " + ", ".join(sorted(denies)))
        return "; ".join(parts) or "allow (default)"
    return str(value)


def audit(doc: dict) -> dict:
    findings: list[dict] = []

    def add(severity: str, where: str, message: str) -> None:
        findings.append({"severity": severity, "where": where, "message": message})

    if not isinstance(doc, dict):
        add("high", "kortix.yaml", "The file is not a mapping; it is not a Kortix manifest.")
        return {"agents": [], "findings": findings, "score": 1}

    # Deprecated keys the schema still accepts and tells you to delete.
    if "kortix_version" in doc:
        add("low", "kortix_version",
            "Deprecated: the format has no version. Delete the line.")
    if "sandboxes" in doc:
        add("low", "sandboxes",
            "Deprecated: use `sandbox.templates`.")

    agents = doc.get("agents") or {}
    if not isinstance(agents, dict):
        add("high", "agents", "`agents` must be a mapping of name to agent block.")
        agents = {}

    default_agent = doc.get("default_agent")
    if default_agent and default_agent not in agents:
        add("high", "default_agent",
            f"`default_agent: {default_agent}` names no agent in this file, so a "
            "session that names none has nothing to run.")

    rows = []
    for name, block in agents.items():
        block = block or {}
        if not isinstance(block, dict):
            add("high", f"agents.{name}", "The agent block is not a mapping.")
            continue

        mode = block.get("mode", "all")
        enabled = block.get("enabled", True)
        perm = block.get("permission")
        grants = {g: _grant(block.get(g)) for g in GRANTS}
        # `tools` is the one grant that defaults to all; the rest default to none.
        if block.get("tools") is None:
            grants["tools"] = "all (default)"
        rows.append({
            "agent": name,
            "mode": mode,
            "enabled": enabled,
            "permission": _permission(perm),
            "grants": grants,
        })

        where = f"agents.{name}"
        if not block.get("prompt") and not block.get("prompt_file"):
            add("medium", where,
                "No `prompt` and no `prompt_file`: the agent runs with no system prompt.")

        if grants["secrets"] == "all":
            add("high", where,
                "`secrets: all` — every secret the project declares is reachable by this agent.")
        if grants["kortix_permissions"] == "all":
            add("high", where,
                "`kortix_permissions: all` — every grantable permission, including the "
                "ones that let an agent merge its own change request.")
        if grants["tools"] == "all" and perm in (None, "allow"):
            add("high", where,
                "`tools: all` with `permission: allow` — every tool runs without asking a person.")
        if perm == "allow":
            add("medium", where,
                "`permission: allow` — no tool call ever stops for approval.")
        if mode in ("primary", "all") and grants["kortix_permissions"] == "all":
            add("high", where,
                "People can start this agent (`mode: primary` or `all`) and it holds every "
                "permission: a person can reach any action through it.")
        if enabled is False:
            add("info", where, "`enabled: false` — no session starts this agent.")

    # Project-level controls an enterprise review asks about.
    if not doc.get("triggers"):
        add("info", "triggers",
            "No `triggers`: nothing runs on a schedule, a webhook or an App event.")
    if not (doc.get("approvals") or doc.get("policy") or doc.get("policies")):
        add("info", "approvals",
            "No `approvals`, `policy` or `policies`: no connector call is held for a person "
            "by a project rule. Per-agent `permission: ask` is the only gate.")

    score = sum(1 for f in findings if f["severity"] == "high")
    return {"agents": rows, "findings": findings, "score": score}


def render(result: dict) -> str:
    out = []
    rows = result["agents"]
    if rows:
        width = max(len(r["agent"]) for r in rows)
        out.append(f"{'agent'.ljust(width)}  mode      permission")
        out.append(f"{'-' * width}  --------  ----------")
        for r in rows:
            flag = "" if r["enabled"] else "  (disabled)"
            out.append(f"{r['agent'].ljust(width)}  {r['mode']:<8}  {r['permission']}{flag}")
        out.append("")
        out.append("grants (omitted = none, except tools = all):")
        for r in rows:
            out.append(f"  {r['agent']}")
            for g, v in r["grants"].items():
                out.append(f"    {g:<18} {v}")
        out.append("")

    if result["findings"]:
        out.append("findings:")
        for f in sorted(result["findings"],
                        key=lambda x: -SEVERITY_ORDER.get(x["severity"], 0)):
            out.append(f"  [{f['severity']:<6}] {f['where']}: {f['message']}")
    else:
        out.append("findings: none")
    out.append("")
    out.append(f"high findings: {result['score']}")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("manifest", nargs="?", default="kortix.yaml")
    ap.add_argument("--json", action="store_true", help="print the result as JSON")
    ap.add_argument("--fail-on", default="high",
                    choices=["info", "low", "medium", "high", "none"],
                    help="exit 1 when a finding at or above this severity exists")
    args = ap.parse_args(argv)

    path = Path(args.manifest)
    if not path.exists():
        print(f"{path}: no such file", file=sys.stderr)
        return 2
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        print(f"{path}: not valid YAML: {exc}", file=sys.stderr)
        return 2

    result = audit(doc)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(render(result))

    if args.fail_on == "none":
        return 0
    floor = SEVERITY_ORDER[args.fail_on]
    worst = max((SEVERITY_ORDER.get(f["severity"], 0) for f in result["findings"]),
                default=-1)
    return 1 if worst >= floor else 0


if __name__ == "__main__":
    raise SystemExit(main())
