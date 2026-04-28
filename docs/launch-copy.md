# Launch Copy

## One-Liner

MCP Guardian is a local security firewall, scanner, and audit layer for Model Context Protocol servers.

## Short Description

MCP Guardian protects AI-agent workflows by enforcing policy between MCP clients and servers. It can block risky tool calls, detect dangerous shell and filesystem behavior, redact secrets, write audit logs, scan MCP server repos, and run in CI as a GitHub Action.

## Website Hero

Secure your MCP servers before agents use them.

MCP Guardian sits between your AI client and MCP servers to block dangerous tools, redact secrets, audit activity, and scan server repos before risky changes ship.

## Problem

MCP makes it easy to connect agents to powerful local and internal tools. The same capability can expose shells, databases, browsers, files, credentials, and cloud APIs to prompt injection or over-broad automation. Most teams need guardrails before they can safely adopt more MCP servers.

## Positioning

MCP Guardian is for developers, security engineers, and platform teams that want practical MCP safety controls without running a remote service or changing every MCP server implementation.

## Key Benefits

- Local-first proxy for stdio MCP servers.
- Policy enforcement for allow, warn, and deny tool rules.
- Shell, filesystem, network, and secret risk detection.
- Secret redaction in arguments, responses, and audit logs.
- Repo and config scanner for pre-adoption review.
- GitHub Action for pull request gates.

## Launch Post

MCP servers are quickly becoming the way AI agents reach real tools: shells, browsers, databases, filesystems, cloud APIs, and internal systems.

That power needs a local trust boundary.

MCP Guardian is a local firewall, scanner, and audit layer for MCP servers. It proxies stdio MCP traffic, evaluates tool calls before they reach the server, blocks risky behavior, redacts secrets, and writes JSONL audit logs you can review locally.

It also includes a repository scanner and GitHub Action so teams can catch risky MCP server changes in pull requests.

Start in monitor mode, review what your agents actually call, then switch to enforce mode when the policy is ready.

```bash
npm install -g mcp-guardian
mcp-guardian scan . --fail-on high
mcp-guardian proxy -- npx -y your-mcp-server
```

## Taglines

- A local firewall for MCP servers.
- Guardrails for agent tool use.
- Secure MCP before it reaches production workflows.
- Scan, proxy, redact, and audit MCP servers locally.
