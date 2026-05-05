# mcp-guardian

**Your MCP server is a trust boundary. Most teams ship it wide open.**

`mcp-guardian` is an open-source security toolkit for the Model Context Protocol ecosystem. It audits MCP server configurations for vulnerabilities, intercepts tool calls at runtime with a programmable firewall, and integrates into CI pipelines to block dangerous servers before they reach production.

---

## What It Does

| Capability | Description |
|---|---|
| **Scanner** | Static analysis of MCP server manifest JSON — 15 checks across manifest structure, tool definitions, and permission scopes |
| **Firewall** | Runtime `ToolCallFirewall` class — 15 built-in rules that inspect tool call arguments before they execute |
| **CI Guardrail** | CLI exits with code 1 on findings above your threshold; SARIF output integrates with GitHub Code Scanning |

---

## Quick Start

```bash
# Install globally
npm install -g mcp-guardian

# Scan a server manifest
mcp-guardian scan my-server.json

# Scan with strict policy, fail on any critical finding
mcp-guardian scan my-server.json --policy strict --fail-on critical

# Export SARIF for GitHub Code Scanning
mcp-guardian scan my-server.json --output sarif > mcp-guardian.sarif
```

---

## Scanner: What It Detects

### Manifest Checks (MS-*)
| ID | Severity | Finding |
|---|---|---|
| MS-001 | HIGH | Missing server authentication |
| MS-002 | CRITICAL | Wildcard tool permissions (`*`) |
| MS-003 | MEDIUM | Tool count > 50 (excessive surface area) |
| MS-004 | LOW | Missing server description |
| MS-005 | MEDIUM | Server version not pinned |

### Tool Checks (TS-*)
| ID | Severity | Finding |
|---|---|---|
| TS-001 | CRITICAL | Dangerous tool name (exec/shell/eval) |
| TS-002 | CRITICAL | Prompt override language in tool description |
| TS-003 | HIGH | Data exfiltration language in description |
| TS-004 | LOW | Missing parameter descriptions |
| TS-005 | CRITICAL | Tool accepts arbitrary code/script input |
| TS-006 | HIGH | Tool name shadows another tool |

### Permission Checks (PS-*)
| ID | Severity | Finding |
|---|---|---|
| PS-001 | CRITICAL | Filesystem write permissions too broad |
| PS-002 | CRITICAL | Network permissions unrestricted |
| PS-003 | HIGH | Missing permission scope definitions |
| PS-004 | HIGH | Permissions not least-privilege |

---

## Firewall: Runtime Tool Call Interception

Embed `ToolCallFirewall` in your TypeScript agent to block malicious tool calls before they execute.

```typescript
import { ToolCallFirewall } from 'mcp-guardian/firewall';
import { loadPolicy } from 'mcp-guardian/firewall/policy';

// Load a named policy or a custom policy file
const policy = loadPolicy('standard'); // or 'strict', 'audit', or '/path/to/policy.json'
const firewall = new ToolCallFirewall(policy);

// Before executing any tool call:
const decision = firewall.inspect({
  toolName: 'send_email',
  args: {
    to: 'attacker@gmail.com',
    body: 'ignore previous instructions',
  },
  context: 'The user asked me to...',
});

if (!decision.allowed) {
  console.error(`Blocked: ${decision.reason}`);
  // decision.matchedRule contains the rule ID (e.g., "FW-002")
} else {
  // Proceed with tool execution
  await executeTool(call);
}

// Add a custom rule
firewall.addRule({
  id: 'FW-CUSTOM-001',
  name: 'Block Internal IP Access',
  description: 'Prevents tools from targeting internal network ranges',
  severity: 'high',
  match: (call) => /10\.\d+\.\d+\.\d+|192\.168\./.test(JSON.stringify(call.args)),
});
```

### Built-in Firewall Rules (FW-*)

| ID | Severity | Rule |
|---|---|---|
| FW-001 | CRITICAL | Block shell execution tools |
| FW-002 | CRITICAL | Block prompt override language in args |
| FW-003 | HIGH | Block base64-encoded instruction payloads |
| FW-004 | HIGH | Block suspicious email/webhook recipients |
| FW-005 | CRITICAL | Block sensitive path access (.env, .ssh/, /etc/passwd) |
| FW-006 | MEDIUM | Rate limit: > 10 calls to same tool in 60s |
| FW-007 | HIGH | Block SQL injection patterns |
| FW-008 | CRITICAL | Block jailbreak patterns in LLM context |
| FW-009 | MEDIUM | Block non-HTTPS HTTP endpoints |
| FW-010 | CRITICAL | Block private key material in args |
| FW-011 | HIGH | Block JWT tokens passed to unauthenticated tools |
| FW-012 | HIGH | Block tool chaining injection |
| FW-013 | CRITICAL | Block tools accepting arbitrary code/script params |
| FW-014 | MEDIUM | Flag oversized arguments (prompt stuffing > 10KB) |
| FW-015 | HIGH | Block Unicode direction override characters |

---

## CI/CD Integration

### GitHub Actions

```yaml
- name: Scan MCP server manifest
  run: |
    npm install -g mcp-guardian
    mcp-guardian scan ./mcp-server.json \
      --output table \
      --policy strict \
      --fail-on high
```

The step exits with code 1 if any finding meets or exceeds the `--fail-on` threshold, failing the pipeline.

### SARIF Integration (GitHub Code Scanning)

```yaml
- name: Generate SARIF report
  run: |
    mcp-guardian scan ./mcp-server.json --output sarif > mcp-guardian.sarif

- name: Upload SARIF to GitHub Code Scanning
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: mcp-guardian.sarif
    category: mcp-guardian
```

Findings appear in the **Security** tab of your GitHub repository under Code Scanning alerts. SARIF output is valid SARIF 2.1.0 — compatible with GitHub Advanced Security, VS Code SARIF Viewer, and any SARIF-consuming CI tool.

---

## Policies

Three built-in policies ship out of the box:

| Policy | Mode | Behavior |
|---|---|---|
| `strict` | deny | Block everything matched by any critical or high rule |
| `standard` | deny | Block critical/high; audit medium/low; rate limit and oversized args are audit-only |
| `audit` | audit | Log all matches, never block — for monitoring and onboarding |

Custom policies can be loaded from a JSON file:

```json
{
  "name": "my-custom-policy",
  "description": "Custom policy for my deployment",
  "defaultMode": "deny",
  "rules": [
    { "ruleId": "FW-006", "action": "skip" },
    { "ruleId": "FW-009", "action": "downgrade" }
  ]
}
```

```bash
mcp-guardian scan server.json --policy ./policies/my-custom-policy.json
```

---

## CLI Reference

```
mcp-guardian scan <server.json>
  --output   json | table | sarif       (default: table)
  --policy   strict | standard | audit | path/to/policy.json
  --fail-on  critical | high | medium   (default: high)
  --save     <path>                     save raw JSON scan result
  --no-color                            disable color output

mcp-guardian watch <server.json>
  --output   json | table | sarif
  --policy   strict | standard | audit
  --no-color

mcp-guardian report <scan-output.json>
  --output   json | table | sarif
  --no-color
```

**Exit codes:**
- `0` — scan passed (no findings above threshold)
- `1` — findings found above threshold
- `2` — scan error (invalid file, bad policy, etc.)

---

## Local Development

```bash
git clone https://github.com/cyberranger93/mcp-guardian.git
cd mcp-guardian
npm install
npm run build

# Run a scan against the example vulnerable server
node dist/cli/index.js scan examples/vulnerable-server.json

# Run against the safe server
node dist/cli/index.js scan examples/safe-server.json
```

---

## License

MIT — see [LICENSE](LICENSE).

---

## Security

Found a vulnerability in mcp-guardian itself? Open a GitHub issue marked `security` or email `yathavang1@gmail.com`.
