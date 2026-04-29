# Demos

These demos are designed for launch videos, docs, and conference walkthroughs.

## Demo 1: Block A Dangerous Shell Command

Goal: show Guardian blocking a destructive or suspicious MCP tool call before it reaches the server.

Setup:

```bash
npm install -g github:cyberranger93/mcp-guardian
mcp-guardian init
```

Run a guarded server:

```bash
mcp-guardian proxy --config .mcp-guardian.json -- node examples/demo-risky-server/server.js
```

Narrative:

1. The MCP client asks the server to run a shell-style tool.
2. The tool arguments contain a dangerous command pattern.
3. Guardian returns a block decision.
4. The audit log records the reason, severity, and rule ID.

Show:

```bash
tail -f .mcp-guardian/audit.jsonl
```

## Demo 2: Monitor Mode Rollout

Goal: show that teams can adopt Guardian without breaking workflows.

Use:

```bash
mcp-guardian proxy --mode monitor -- npx -y some-mcp-server
```

Narrative:

1. Guardian observes normal tool traffic.
2. Warnings are logged but not blocked.
3. The team promotes noisy warnings into explicit allow rules or deny rules.
4. The policy is switched to enforce mode.

## Demo 3: CI Scan Prevents Risky MCP Server Drift

Goal: show Guardian as a pull request gate.

Use the workflow in `examples/github-actions/mcp-guardian.yml`.

Narrative:

1. A pull request adds a generic shell tool or hardcoded token.
2. The GitHub Action runs `mcp-guardian scan`.
3. The check fails on `high` or `critical`.
4. The author replaces the generic tool with a narrow operation.

## Demo 4: Secret Redaction

Goal: show that auditability does not require leaking credentials.

Narrative:

1. A tool call contains a token-like value.
2. Guardian detects and redacts it in audit output.
3. The decision still includes enough context for review.

Expected audit shape:

```json
{
  "toolName": "http_request",
  "decision": {
    "action": "warn",
    "severity": "high",
    "reasons": ["Potential secret in tool arguments"]
  },
  "arguments": {
    "headers": {
      "authorization": "[REDACTED]"
    }
  },
  "redacted": true
}
```
