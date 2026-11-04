# agentic-enterprise-audit — an open-source audit for a Kortix project

Kortix is open source, and this is a small tool for the question an enterprise review asks first: **what can each of our agents actually reach?**

An agentic enterprise runs its work through agents. That is the point, and it is also the risk: an agent that holds every secret, every tool and every permission is the widest access in the company, held by something that never gets tired. Kortix keeps the answer in one file — `kortix.yaml` — because agents, skills, memory and connectors are files in a git repo you own. This script reads that file and prints, per agent, its mode, its permission and every grant, then the findings that matter.

It is a reader, not a linter for style. It answers three questions:

1. What does this agent hold? (`tools`, `skills`, `connectors`, `secrets`, `kortix_permissions`, `subagents`, `commands`, `extensions`, `apps`)
2. What does it do without asking a person? (`permission`)
3. Can a person reach that reach through it? (`mode`)

## Quick start

```bash
git clone https://github.com/Kortix-seo/agentic-enterprise-audit
cd agentic-enterprise-audit
pip install pyyaml        # or: pip install -e .

python audit.py path/to/kortix.yaml
python audit.py path/to/kortix.yaml --json
python audit.py path/to/kortix.yaml --fail-on high   # exit 1 on a high finding
```

Exit codes: `0` clean, `1` findings at or above `--fail-on` (default `high`), `2` the file is missing or is not valid YAML. That makes it usable as a step in CI: a manifest that grants a new agent every secret fails the build.

## What it checks

| Check | Severity | Why it matters |
| --- | --- | --- |
| `secrets: all` | high | Every secret the project declares is reachable by that agent. |
| `kortix_permissions: all` | high | Every grantable permission, including the ones that let an agent merge its own change request. |
| `tools: all` with `permission: allow` | high | Every tool runs without asking a person. |
| `mode: primary` or `all` with `kortix_permissions: all` | high | People can start the agent, so a person can reach any action through it. |
| `permission: allow` | medium | No tool call ever stops for approval. |
| No `prompt` and no `prompt_file` | medium | The agent runs with no system prompt. |
| `default_agent` names no agent | high | A session that names none has nothing to run. |
| `kortix_version`, `sandboxes` | low | Deprecated keys the schema tells you to delete. |
| No `triggers` | info | Nothing runs on a schedule, a webhook or an App event. |
| No `approvals`, `policy` or `policies` | info | No connector call is held for a person by a project rule. |

The defaults are the reason the first four checks exist. Grants are deny-by-default — an omitted `skills`, `subagents`, `commands`, `extensions`, `connectors`, `secrets` or `kortix_permissions` grant is none — but `tools` defaults to `all` and `permission` defaults to `allow`. A manifest that never mentions either gets both.

## What it prints

`examples/kortix.yaml` is the starter's own `worker` agent plus a second agent added in a hurry. Running the audit on it:

```
agent            mode      permission
---------------  --------  ----------
worker           primary   allow
release-manager  primary   allow

grants (omitted = none, except tools = all):
  worker
    tools              all
    skills             all
    subagents          none
    commands           none
    extensions         none
    connectors         all
    secrets            all
    kortix_permissions all
    apps               none
  ...

findings:
  [high  ] agents.worker: `secrets: all` — every secret the project declares is reachable by this agent.
  [high  ] agents.worker: `kortix_permissions: all` — every grantable permission, including the ones that let an agent merge its own change request.
  [high  ] agents.worker: `tools: all` with `permission: allow` — every tool runs without asking a person.
  [high  ] agents.worker: People can start this agent (`mode: primary` or `all`) and it holds every permission: a person can reach any action through it.
  ...

high findings: 8
```

`examples/kortix-tightened.yaml` is the same project with each agent given the grants its job needs and the tools that change something set to `ask`. It comes back with `findings: none` and exit code 0. The full output of both runs is in `examples/audit-output.out` and `examples/audit-output-tightened.out`.

## What it does not do

- It does not read the files the manifest points at. A `prompt_file` that does not exist, or a skill folder that is missing, is not caught here; `kortix validate` checks the manifest against the schema and lints the sandbox templates, and `kortix doctor` starts a throwaway session and checks the project end to end.
- It does not know your account's roles. `kortix_permissions` is capped by the agent's ceiling role, which lives in the account, not in the file.
- It does not decide what is right for you. A `worker` with `tools: all` and `permission: allow` is the starter's own default, and for a first project it is a reasonable one. The audit's job is to make the choice visible, not to make it for you.

## Where the rules come from

- The schema: <https://kortix.com/schema/kortix.schema.json> (`kortix schema` prints the same document).
- The reference: <https://kortix.com/docs/developers>.
- The starter manifest this example copies: `packages/starter/templates/base/kortix.yaml` in [the Kortix repository](https://github.com/kortix-ai/CompanyOS).

## Reading next

Two pages on the campaign site go with this tool. [The open-source agentic enterprise platform](https://agenticenterpriseguide.com/open-source-agentic-enterprise-platform) sets out what a company installs and governs, and which parts a framework leaves you to build. [The agentic enterprise architecture](https://agenticenterpriseguide.com/agentic-enterprise-architecture) walks the two files a session reads before it does anything — the manifest this script audits, and the agent's own markdown prompt.

## Tests

```bash
python -m unittest discover -s tests
```

## Contributing

Open an issue with the manifest shape that produced a wrong or missing finding, and the output you expected. A check is worth adding when it is a fact the schema states and a reviewer would ask about.
