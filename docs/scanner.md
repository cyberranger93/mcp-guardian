# Scanner Guide

The scanner reviews repositories and MCP-related config for risky patterns before an MCP server is connected to an agent.

## Run Locally

```bash
mcp-guardian scan .
```

Fail on high or critical findings:

```bash
mcp-guardian scan . --fail-on high
```

Use an explicit config:

```bash
mcp-guardian scan . --config .mcp-guardian.json --fail-on critical
```

## What To Scan

Scan:

- MCP server repositories before first use.
- Pull requests that add or modify MCP tools.
- MCP client config files.
- Internal automation repos that expose shell, database, browser, filesystem, or cloud tools.

## Finding Severity

| Severity | Meaning |
| --- | --- |
| `info` | Useful context or inventory. |
| `low` | Low-risk pattern worth reviewing. |
| `medium` | Potentially risky behavior or weak defaults. |
| `high` | Risky behavior that should be fixed or justified. |
| `critical` | Likely secret exposure, destructive operation, or exfiltration path. |

## Recommended CI Gate

For new projects:

```bash
mcp-guardian scan . --fail-on high
```

For an existing codebase during rollout:

```bash
mcp-guardian scan . --fail-on critical
```

After baseline cleanup, tighten the gate to `high`.

## Triage Workflow

1. Confirm whether the finding is reachable from an MCP tool.
2. Remove unused risky capability.
3. Replace generic shell or database tools with narrow task-specific tools.
4. Move secrets to a secret manager or environment boundary.
5. Add explicit policy if the behavior is required and reviewed.

## CI Artifacts

Store scanner output and audit logs as CI artifacts when investigating policy changes. Do not publish unredacted scan output from private repositories.
