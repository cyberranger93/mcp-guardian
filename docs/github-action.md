# GitHub Action

Use MCP Guardian in GitHub Actions to scan MCP server repositories and fail pull requests when risky behavior is introduced.

## Basic Workflow

```yaml
name: MCP Guardian

on:
  pull_request:
  push:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: cyberranger93/mcp-guardian@v0
        with:
          path: .
          fail-on: high
          config: .mcp-guardian.json
```

## Inputs

| Input | Default | Description |
| --- | --- | --- |
| `path` | `.` | Repository path to scan. |
| `config` | Auto-discovered | Optional Guardian policy path. |
| `fail-on` | `critical` | Minimum severity that fails the job. |
| `args` | Empty | Extra CLI arguments for advanced scanner use. |

## Rollout Strategy

Start with:

```yaml
fail-on: critical
```

After the team has reviewed the first baseline, tighten to:

```yaml
fail-on: high
```

Use explicit policy exceptions instead of permanently weakening the gate.

## Monorepos

Run one job per MCP server package when different teams own different policies:

```yaml
strategy:
  matrix:
    package:
      - packages/github-mcp
      - packages/database-mcp
      - packages/browser-mcp

steps:
  - uses: actions/checkout@v4
  - uses: cyberranger93/mcp-guardian@v0
    with:
      path: ${{ matrix.package }}
      config: ${{ matrix.package }}/.mcp-guardian.json
      fail-on: high
```

## Artifact Guidance

If scanner output is uploaded as an artifact, keep retention short and avoid publishing artifacts from private repos. Even redacted findings can reveal internal file names, architecture, or tool names.
