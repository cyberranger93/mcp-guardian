# Policy Guide

MCP Guardian policy is a JSON document. By default, Guardian looks for:

- `.mcp-guardian.json`
- `mcp-guardian.config.json`
- `mcp-guardian.json`

You can also pass a config path with `--config` or set `MCP_GUARDIAN_CONFIG`.

## Top-Level Fields

```json
{
  "version": "0.1",
  "mode": "enforce",
  "audit": {},
  "redaction": {},
  "tools": {},
  "rules": {},
  "scanner": {}
}
```

`mode` may be `enforce` or `monitor`.

Use `monitor` when introducing Guardian to an existing workflow. Use `enforce` when the policy is ready to block high-risk activity.

## Tool Rules

```json
{
  "tools": {
    "allow": [],
    "deny": ["shell", "exec", "dangerously_*", "*unsafe*"],
    "warn": ["browser_*", "http_*"]
  }
}
```

Tool rules match MCP tool names. Use exact names for known tools and glob-style patterns for tool families.

Recommended defaults:

- Deny generic shell and exec tools unless they are wrapped by a narrow, reviewed interface.
- Warn on browser and HTTP tools during rollout.
- Prefer explicit allowlists for production agent workflows.

## Shell Rules

```json
{
  "rules": {
    "shell": {
      "blockDangerousCommands": true,
      "denyPatterns": [
        "curl.+\\|\\s*(sh|bash|pwsh|powershell)",
        "Invoke-WebRequest.+\\|",
        "git\\s+reset\\s+--hard",
        "rm\\s+-rf\\s+(/|\\*)"
      ],
      "warnPatterns": [
        "npm\\s+install",
        "pip\\s+install",
        "docker\\s+run"
      ]
    }
  }
}
```

Use deny patterns for commands that should never be executed by an agent. Use warn patterns for commands that may be legitimate but should be visible in audit logs.

## Filesystem Rules

```json
{
  "rules": {
    "filesystem": {
      "blockSensitiveReads": true,
      "denyPaths": [
        ".env",
        ".aws/credentials",
        ".ssh/id_rsa",
        ".ssh/id_ed25519"
      ],
      "warnOnAbsolutePaths": true
    }
  }
}
```

Filesystem rules are meant to reduce accidental credential exposure and broad host inspection. They are not a replacement for OS-level file permissions.

## Network Rules

```json
{
  "rules": {
    "network": {
      "denyHosts": ["metadata.google.internal", "169.254.169.254"],
      "warnHosts": ["pastebin.com", "webhook.site"]
    }
  }
}
```

Use network deny rules for metadata services, internal-only hosts, or known exfiltration destinations. Use warn rules for destinations that require human review.

## Secret Rules

```json
{
  "rules": {
    "secrets": {
      "blockOnSecret": true
    }
  },
  "redaction": {
    "enabled": true,
    "redactResponses": true
  }
}
```

When `blockOnSecret` is enabled, Guardian can block tool calls that include values recognized as secrets. Keep redaction enabled for audit logs in team environments.

## Scanner Rules

```json
{
  "scanner": {
    "maxFileSizeBytes": 1000000,
    "exclude": [
      ".git",
      "node_modules",
      "dist",
      "coverage",
      ".next",
      ".turbo",
      ".mcp-guardian"
    ]
  }
}
```

Exclude generated directories to keep scans fast and reduce noise.

## Rollout Policy

Start with the monitor rollout example in `examples/policies/monitor-rollout.json`. Review audit logs for a few normal sessions, promote high-confidence warnings to denies, then switch to enforce mode.
