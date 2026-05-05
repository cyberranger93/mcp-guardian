import type { FirewallRule, ToolCall } from '../types.js';

// ─── Helpers ────────────────────────────────────────────────────────────────

function stringifyArgs(args: Record<string, unknown>): string {
  return JSON.stringify(args).toLowerCase();
}

function getArgValues(args: Record<string, unknown>): string[] {
  return Object.values(args).map((v) =>
    typeof v === 'string' ? v : JSON.stringify(v),
  );
}

function getArgValuesRaw(args: Record<string, unknown>): string[] {
  return Object.values(args).map((v) =>
    typeof v === 'string' ? v : JSON.stringify(v),
  );
}

// Rate-limit state: toolName → timestamps of recent calls
const callTimestamps = new Map<string, number[]>();

function isRateLimited(toolName: string, windowMs: number, limit: number): boolean {
  const now = Date.now();
  const timestamps = callTimestamps.get(toolName) ?? [];
  const recent = timestamps.filter((t) => now - t < windowMs);
  recent.push(now);
  callTimestamps.set(toolName, recent);
  return recent.length > limit;
}

// ─── 15 Built-in Rules ───────────────────────────────────────────────────────

export const builtinRules: FirewallRule[] = [
  {
    id: 'FW-001',
    name: 'Block Shell Execution Tools',
    description:
      'Blocks tool calls to tools with names suggesting OS-level code execution (exec, shell, system, run_command, etc.).',
    severity: 'critical',
    match(call: ToolCall): boolean {
      const dangerousNames = /\b(exec|shell|system|run_command|spawn|popen|subprocess|bash|cmd|powershell)\b/i;
      return dangerousNames.test(call.toolName);
    },
  },

  {
    id: 'FW-002',
    name: 'Block Prompt Override Language',
    description:
      'Blocks tool call arguments containing phrases used in prompt injection attacks like "ignore previous instructions" or "override".',
    severity: 'critical',
    match(call: ToolCall): boolean {
      const raw = stringifyArgs(call.args);
      const patterns = [
        'ignore previous',
        'ignore all previous',
        'override instructions',
        'disregard your',
        'forget your instructions',
        'new instructions:',
        'your new role',
        'act as if',
        'you are now',
        'from now on ignore',
      ];
      return patterns.some((p) => raw.includes(p));
    },
  },

  {
    id: 'FW-003',
    name: 'Block Base64-Encoded Instruction Payloads',
    description:
      'Detects base64-encoded strings in arguments that, when decoded, contain instruction-like content.',
    severity: 'high',
    match(call: ToolCall): boolean {
      const base64Pattern = /^[A-Za-z0-9+/]{20,}={0,2}$/;
      const instructionKeywords = /ignore|override|system|prompt|instruction|role|assistant/i;
      for (const val of getArgValuesRaw(call.args)) {
        if (base64Pattern.test(val.trim())) {
          try {
            const decoded = Buffer.from(val.trim(), 'base64').toString('utf8');
            if (instructionKeywords.test(decoded)) return true;
          } catch {
            // not valid base64 — ignore
          }
        }
      }
      return false;
    },
  },

  {
    id: 'FW-004',
    name: 'Block Suspicious Email / Webhook Recipients',
    description:
      'Blocks email or webhook tool calls where the recipient looks like data exfiltration (free email domains, suspicious TLDs, or unexpected external endpoints).',
    severity: 'high',
    match(call: ToolCall): boolean {
      const isEmailOrWebhookTool = /\b(send_email|email|webhook|notify|post_to|http_post|slack|discord)\b/i.test(
        call.toolName,
      );
      if (!isEmailOrWebhookTool) return false;
      const raw = stringifyArgs(call.args);
      const suspiciousPatterns = [
        /@(gmail|yahoo|hotmail|protonmail|tutanota|guerrillamail|mailinator)\.(com|net|org)/i,
        /https?:\/\/(?!.*\.(internal|corp|localhost))[^"'\s]{3,}\.(xyz|top|tk|ml|ga|cf|gq)\b/i,
        /ngrok\.io/i,
        /requestbin\./i,
        /webhook\.site/i,
        /pipedream\.net/i,
      ];
      return suspiciousPatterns.some((p) => p.test(raw));
    },
  },

  {
    id: 'FW-005',
    name: 'Block Sensitive Path Access',
    description:
      'Blocks file operation tool calls that reference sensitive system paths such as /etc/passwd, .ssh/, .env, or credential stores.',
    severity: 'critical',
    match(call: ToolCall): boolean {
      const raw = stringifyArgs(call.args);
      const sensitivePaths = [
        '/etc/passwd',
        '/etc/shadow',
        '/etc/hosts',
        '\\.ssh/',
        '\\.ssh\\\\',
        '\\.env',
        '\\.aws/credentials',
        '\\.kube/config',
        'id_rsa',
        'id_ed25519',
        '/proc/self',
        'c:\\\\windows\\\\system32',
        'c:/windows/system32',
        '\\.git/config',
        'authorized_keys',
        'known_hosts',
      ];
      return sensitivePaths.some((p) => new RegExp(p, 'i').test(raw));
    },
  },

  {
    id: 'FW-006',
    name: 'Rate Limit: Repeated Tool Calls',
    description:
      'Flags when more than 10 calls to the same tool occur within a 60-second window — a pattern consistent with automated abuse or runaway loops.',
    severity: 'medium',
    match(call: ToolCall): boolean {
      return isRateLimited(call.toolName, 60_000, 10);
    },
  },

  {
    id: 'FW-007',
    name: 'Block SQL Injection Patterns',
    description:
      'Blocks tool call arguments containing destructive or injection SQL patterns such as DROP TABLE, DELETE FROM, or inline comment sequences.',
    severity: 'high',
    match(call: ToolCall): boolean {
      const raw = stringifyArgs(call.args);
      const sqlPatterns = [
        /drop\s+table/i,
        /delete\s+from/i,
        /truncate\s+table/i,
        /alter\s+table/i,
        /insert\s+into.*select/i,
        /union\s+select/i,
        /;?\s*--\s/,
        /\/\*.*\*\//,
        /xp_cmdshell/i,
        /exec\s*\(/i,
        /information_schema/i,
        /sleep\s*\(\d+\)/i,
        /benchmark\s*\(/i,
      ];
      return sqlPatterns.some((p) => p.test(raw));
    },
  },

  {
    id: 'FW-008',
    name: 'Block Jailbreak Patterns in Context',
    description:
      'Blocks tool calls where the surrounding LLM context contains known jailbreak or adversarial role-play patterns.',
    severity: 'critical',
    match(call: ToolCall): boolean {
      const ctx = (call.context ?? '').toLowerCase();
      if (!ctx) return false;
      const jailbreakPatterns = [
        'dan mode',
        'developer mode enabled',
        'jailbreak',
        'no restrictions',
        'without ethical',
        'pretend you have no',
        'imagine you are an ai with no',
        'act as an unrestricted',
        'do anything now',
        'you are dAN',
        'token budget bypassed',
        'guardrails disabled',
      ];
      return jailbreakPatterns.some((p) => ctx.includes(p));
    },
  },

  {
    id: 'FW-009',
    name: 'Block Non-HTTPS HTTP Endpoints',
    description:
      'Blocks tool calls that target plain HTTP (non-HTTPS) endpoints, which are susceptible to interception and MITM attacks.',
    severity: 'medium',
    match(call: ToolCall): boolean {
      const raw = stringifyArgs(call.args);
      // Match http:// but not https://
      return /http:\/\/(?!localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)/.test(raw);
    },
  },

  {
    id: 'FW-010',
    name: 'Block Private Key Material in Args',
    description:
      'Blocks tool calls containing PEM-encoded private keys or similar cryptographic secrets being passed as arguments.',
    severity: 'critical',
    match(call: ToolCall): boolean {
      const raw = stringifyArgs(call.args);
      const keyPatterns = [
        /-----BEGIN RSA PRIVATE KEY-----/i,
        /-----BEGIN PRIVATE KEY-----/i,
        /-----BEGIN EC PRIVATE KEY-----/i,
        /-----BEGIN OPENSSH PRIVATE KEY-----/i,
        /-----BEGIN PGP PRIVATE KEY BLOCK-----/i,
      ];
      return keyPatterns.some((p) => p.test(raw));
    },
  },

  {
    id: 'FW-011',
    name: 'Block JWT Tokens Passed to Unauthenticated Tools',
    description:
      'Detects when a JWT token is passed as an argument to a tool that does not appear to handle authentication.',
    severity: 'high',
    match(call: ToolCall): boolean {
      // JWT pattern: three base64url segments separated by dots
      const jwtPattern = /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/;
      const raw = stringifyArgs(call.args);
      if (!jwtPattern.test(raw)) return false;
      // Flag if the tool name doesn't suggest it handles auth
      const authTools = /\b(auth|login|token|refresh|verify|oauth|jwt)\b/i;
      return !authTools.test(call.toolName);
    },
  },

  {
    id: 'FW-012',
    name: 'Block Tool Chaining Injection',
    description:
      'Blocks tool call arguments that reference other tool names, which can be used to chain unintended tool invocations.',
    severity: 'high',
    match(call: ToolCall): boolean {
      const raw = stringifyArgs(call.args);
      // Look for patterns like: "call tool X with...", "invoke X", "use the X tool"
      const chainingPatterns = [
        /\bcall\s+(the\s+)?tool\b/i,
        /\binvoke\s+\w+\s*\(/i,
        /\buse\s+the\s+\w+\s+tool\b/i,
        /\btool_call\s*:/i,
        /\bfunction_call\s*:/i,
        /"tool"\s*:\s*"[^"]+"/,
        /"function"\s*:\s*"[^"]+"/,
      ];
      return chainingPatterns.some((p) => p.test(raw));
    },
  },

  {
    id: 'FW-013',
    name: 'Block Arbitrary Code / Script Parameters',
    description:
      'Blocks tool calls to tools that accept parameters named "code", "script", "eval", or "execute" — high-risk patterns for remote code execution.',
    severity: 'critical',
    match(call: ToolCall): boolean {
      const dangerousParamNames = /^(code|script|eval|execute|payload|command|cmd|expression|expr)$/i;
      return Object.keys(call.args).some((key) => dangerousParamNames.test(key));
    },
  },

  {
    id: 'FW-014',
    name: 'Flag Oversized Arguments (Prompt Stuffing)',
    description:
      'Flags tool calls where any single argument exceeds 10,000 characters — a common vector for hiding malicious instructions inside large payloads.',
    severity: 'medium',
    match(call: ToolCall): boolean {
      return getArgValues(call.args).some((v) => v.length > 10_000);
    },
  },

  {
    id: 'FW-015',
    name: 'Block Unicode Direction Override Characters',
    description:
      'Blocks tool call arguments containing Unicode bidirectional control characters (U+202A–U+202E, U+2066–U+2069) used to visually spoof content.',
    severity: 'high',
    match(call: ToolCall): boolean {
      // Bidirectional control characters
      const bidiPattern = /[‪-‮⁦-⁩‏‎]/;
      return getArgValuesRaw(call.args).some((v) => bidiPattern.test(v));
    },
  },
];
