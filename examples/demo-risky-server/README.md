# Demo Risky Server

This directory is a documentation-only demo fixture for launch walkthroughs. It represents the kind of MCP server behavior that Guardian is designed to monitor or block:

- Generic shell execution tools.
- Sensitive file reads.
- Network calls to paste or webhook collection services.
- Tool arguments that may contain secrets.

Use this fixture as a script outline for demos rather than as production server code.

## Demo Flow

1. Start Guardian in monitor mode and show that risky calls are logged.
2. Switch to enforce mode.
3. Repeat the same tool call.
4. Show the block decision and redacted audit event.

```bash
mcp-guardian proxy --mode monitor -- node examples/demo-risky-server/server.js
mcp-guardian proxy --mode enforce -- node examples/demo-risky-server/server.js
```

Expected result in enforce mode:

```json
{
  "action": "block",
  "severity": "critical",
  "reasons": [
    "Tool is denied by policy",
    "Command matches dangerous shell pattern"
  ]
}
```
