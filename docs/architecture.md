# Architecture

MCP Guardian is designed as a local control plane for stdio-based MCP servers.

## Components

### CLI

The CLI exposes developer workflows:

- `init` creates a starter policy.
- `scan` reviews repositories, MCP config files, and server source for risky patterns.
- `proxy` launches a target MCP server command and forwards JSON-RPC over stdio.

### Stdio Proxy

The proxy runs between an MCP client and server:

```text
MCP client <-> MCP Guardian <-> MCP server
```

The proxy reads JSON-RPC messages from the client, identifies tool calls, evaluates policy, optionally redacts arguments, and forwards allowed messages to the server. Responses are streamed back through the same path so response redaction and audit logging can be applied consistently.

### Policy Engine

The policy engine returns a decision for each relevant event:

- `allow`: forward the request.
- `warn`: forward the request and record a warning.
- `block`: stop the request and return an MCP-compatible error.

Each decision includes a severity, risk score, reasons, and rule IDs so audit events can be reviewed without reverse-engineering policy behavior.

### Detectors

Detectors are grouped by risk domain:

- Tool name allow, warn, and deny patterns.
- Shell command risk detection.
- Filesystem sensitive path detection.
- Network host warnings and denials.
- Secret detection and redaction.
- Repository and config scanning.

### Redaction

Redaction runs before data is written to audit logs. When response redaction is enabled, it also applies to server responses before they return to the client.

### Audit Writer

Audit logs are newline-delimited JSON events. JSONL keeps logs easy to append, stream, archive, and inspect with normal command-line tools.

## Message Flow

```text
1. MCP client sends JSON-RPC message.
2. Guardian parses the message.
3. If the message is not a tool call, Guardian forwards it.
4. If the message is a tool call, Guardian extracts the tool name and arguments.
5. Policy rules produce an allow, warn, or block decision.
6. Guardian writes a redacted audit event.
7. Allowed and warned calls are forwarded to the server.
8. Blocked calls return an error to the client.
9. Server responses are optionally redacted and audited.
```

## Trust Boundaries

MCP Guardian protects the boundary between the MCP client and MCP server. It does not make an untrusted MCP server safe by itself. A malicious server may still perform side effects during startup or inside allowed tools. Use Guardian alongside process isolation, least-privilege credentials, pinned dependencies, and code review.

## Deployment Models

### Local Developer Workstation

Use Guardian as the configured MCP server command in a local AI coding client. Start with monitor mode, review audit logs, then switch to enforce mode.

### Team Policy

Commit `.mcp-guardian.json` to repositories that use MCP servers. Keep server-specific exceptions explicit and reviewed.

### CI Scanner

Run `mcp-guardian scan` in pull requests to detect new risky tools, suspicious shell patterns, hardcoded secrets, and unsafe MCP configuration drift.
