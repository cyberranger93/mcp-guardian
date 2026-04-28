# Threat Model

MCP Guardian reduces risk at the MCP client/server boundary. It is most useful when an AI agent can request actions from tools that affect a local machine, source repository, credentials, databases, browsers, or network services.

## Assets

MCP Guardian is intended to protect:

- Source code and local working trees.
- Secrets in files, environment variables, prompts, tool arguments, and responses.
- Developer machines and CI runners.
- Internal databases, cloud accounts, and admin APIs exposed through MCP tools.
- Auditability for agent-driven actions.

## Trust Assumptions

Guardian assumes:

- The local operating system and Node.js runtime are trusted enough to run Guardian.
- The configured policy is reviewed and controlled by the user or team.
- The MCP client can be configured to launch Guardian instead of directly launching the MCP server.
- The MCP server may be buggy, over-permissive, or untrusted.

Guardian does not assume:

- The model will always make safe requests.
- Tool descriptions are honest or complete.
- Third-party MCP servers are safe by default.
- Audit logs are safe to publish without redaction.

## In-Scope Threats

### Prompt-Injection Tool Abuse

An attacker-controlled document, website, issue, or dependency tries to convince the model to invoke risky tools.

Guardian mitigation:

- Tool deny and warn rules.
- Shell, filesystem, network, and secret detectors.
- Enforced block decisions before forwarding tool calls.

### Generic Shell Or Exec Tools

An MCP server exposes a broad command-execution interface.

Guardian mitigation:

- Deny tool names such as `shell` and `exec`.
- Detect dangerous command patterns.
- Warn on package installation, containers, and other high-impact commands.

### Credential Exfiltration

A tool call attempts to read `.env`, SSH keys, cloud credentials, or token-like values and send them to a network destination.

Guardian mitigation:

- Sensitive path rules.
- Secret detection.
- Redaction before audit logging.
- Network host warnings and denials.

### Risky Repository Changes

A pull request adds an unsafe MCP tool, hardcoded credential, or suspicious config.

Guardian mitigation:

- Repository scanner.
- GitHub Action gating.
- Severity-based CI failure thresholds.

## Out-of-Scope Threats

Guardian is not designed to stop:

- Malicious behavior that happens during MCP server startup before Guardian sees a tool call.
- Side effects inside an allowed tool after Guardian forwards the request.
- Kernel, runtime, or container escapes.
- Fully compromised developer machines.
- Network traffic made directly by the MCP server outside the proxied protocol.

Use OS sandboxing, containers, least-privilege tokens, outbound firewall rules, dependency review, and pinned versions for those risks.

## Security Objectives

1. Give developers a clear local enforcement point for MCP tool calls.
2. Make dangerous operations blockable by default.
3. Make adoption practical through monitor mode.
4. Preserve useful auditability while redacting secrets.
5. Shift MCP server review left with a repo scanner and CI action.

## Recommended Baseline

- Run untrusted MCP servers in isolated project directories.
- Avoid generic shell, exec, SQL, browser, and filesystem tools in production workflows.
- Prefer narrow tools with explicit schemas.
- Enable audit logs and redaction.
- Start new projects with `--fail-on high` in CI.
- Treat policy exceptions like code: review them in pull requests.
