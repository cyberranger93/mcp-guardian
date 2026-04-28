import { DEFAULT_CONFIG, mergeConfig } from "./config.js";
import type { GuardianConfig, PolicyDecision, Severity, ToolCall } from "./types.js";
import { containsSecret } from "./redaction.js";

const SHELL_TOOL_NAMES = new Set(["shell", "exec", "command", "run_command", "terminal"]);

const DANGEROUS_COMMAND_PATTERNS: Array<{ severity: Severity; pattern: RegExp; reason: string }> = [
  {
    severity: "critical",
    pattern: /^(?:cmd|cmd\.exe|sh|bash|zsh|fish|powershell|powershell\.exe|pwsh|pwsh\.exe)(?:\s|$)/i,
    reason: "Shell command launches through a shell executable."
  },
  {
    severity: "critical",
    pattern: /\b(?:curl|wget|Invoke-WebRequest|iwr)\b[\s\S]{0,500}[|;&]\s*(?:sh|bash|zsh|pwsh|powershell|cmd|python|node)\b/i,
    reason: "Shell command pipes remote content into an interpreter."
  },
  {
    severity: "critical",
    pattern: /\brm\s+-[^\n]*r[^\n]*f\b|\bRemove-Item\b[\s\S]{0,200}\b-Recurse\b[\s\S]{0,200}\b-Force\b|\b(?:del|erase)\b[^\n]*(?:\/s|\/q)/i,
    reason: "Shell command appears to recursively delete files."
  },
  {
    severity: "high",
    pattern: /\b(?:git\s+reset\s+--hard|git\s+clean\s+-[^\n]*f|git\s+checkout\s+--\s+\.)\b/i,
    reason: "Shell command can destroy uncommitted source changes."
  },
  {
    severity: "critical",
    pattern: /\b(?:cat|type|Get-Content|gc)\b[\s\S]{0,200}(?:\.env|id_rsa|id_ed25519|credentials|token|secret|password)/i,
    reason: "Shell command attempts to read credential-like files."
  },
  {
    severity: "critical",
    pattern: /\b(?:Set-MpPreference|DisableRealtimeMonitoring|netsh\s+advfirewall|iptables\s+-F|spctl\s+--master-disable)\b/i,
    reason: "Shell command appears to weaken host security controls."
  },
  {
    severity: "critical",
    pattern: /\b(?:chmod\s+777|mkfs|dd\s+if=|format\s+[A-Z]:|shutdown|reboot)\b/i,
    reason: "Shell command can damage disks, permissions, or host availability."
  }
];

const SENSITIVE_PATH_PATTERNS: Array<{ pattern: RegExp; reason: string }> = [
  {
    pattern: /(^|[\\/])\.env(?:\.[A-Za-z0-9_-]+)?\b/i,
    reason: "Tool arguments reference an environment file."
  },
  {
    pattern: /(^|[\\/])\.ssh[\\/](?:id_rsa|id_ed25519|config|known_hosts)\b/i,
    reason: "Tool arguments reference SSH material."
  },
  {
    pattern: /(^|[\\/])(?:\.aws[\\/]credentials|\.azure|\.config[\\/]gcloud|credentials\.json)\b/i,
    reason: "Tool arguments reference cloud credential material."
  }
];

const DESTRUCTIVE_SQL_PATTERNS: Array<{ pattern: RegExp; reason: string }> = [
  {
    pattern: /\b(?:DROP\s+(?:DATABASE|SCHEMA|TABLE)|TRUNCATE\s+TABLE)\b/i,
    reason: "Tool arguments contain destructive database DDL."
  },
  {
    pattern: /\b(?:DELETE\s+FROM|UPDATE\s+\w+)\b(?![\s\S]{0,240}\bWHERE\b)/i,
    reason: "Tool arguments contain DELETE or UPDATE without a nearby WHERE clause."
  }
];

export function evaluatePolicy(toolCall: ToolCall, config: GuardianConfig = DEFAULT_CONFIG): PolicyDecision {
  const effective = mergeConfig(DEFAULT_CONFIG, config);
  const reasons: string[] = [];
  const ruleIds: string[] = [];
  let action: PolicyDecision["action"] = "allow";
  let severity: Severity = "info";
  let riskScore = 0;

  const toolName = toolCall.name;
  const serializedArguments = safeStringify(toolCall.arguments);

  if (matchesAny(toolName, effective.tools?.deny ?? [])) {
    block("tool.deny", "high", 90, `Tool '${toolName}' is denied by policy.`);
  } else if (matchesAny(toolName, effective.tools?.warn ?? [])) {
    warn("tool.warn", `Tool '${toolName}' is configured for warning.`);
  }

  const allowList = effective.tools?.allow ?? [];
  if (allowList.length > 0 && !matchesAny(toolName, allowList)) {
    block("tool.not_allowlisted", "high", 80, `Tool '${toolName}' is not in the allow list.`);
  }

  const command = extractCommand(toolCall);
  if (command && effective.rules?.shell?.blockDangerousCommands) {
    for (const rule of DANGEROUS_COMMAND_PATTERNS) {
      if (rule.pattern.test(command)) {
        block("shell.dangerous_command", rule.severity, rule.severity === "critical" ? 95 : 85, rule.reason);
        break;
      }
    }
  }

  for (const pattern of effective.rules?.shell?.denyPatterns ?? []) {
    if (command && new RegExp(pattern, "i").test(command)) {
      block("shell.deny_pattern", "high", 85, "Shell command matches a configured deny pattern.");
      break;
    }
  }

  for (const pattern of effective.rules?.shell?.warnPatterns ?? []) {
    if (command && action === "allow" && new RegExp(pattern, "i").test(command)) {
      warn("shell.warn_pattern", "Shell command matches a configured warn pattern.");
      break;
    }
  }

  if (effective.rules?.secrets?.blockOnSecret && containsSecret(toolCall.arguments)) {
    block("secrets.argument", "critical", 92, "Tool arguments appear to contain a secret.");
  }

  if (isFilesystemTool(toolName) && effective.rules?.filesystem?.blockSensitiveReads !== false) {
    for (const rule of SENSITIVE_PATH_PATTERNS) {
      if (rule.pattern.test(serializedArguments)) {
        block("fs.sensitive_path", "critical", 90, rule.reason);
      }
    }
  }

  for (const deniedPath of effective.rules?.filesystem?.denyPaths ?? []) {
    if (serializedArguments.toLowerCase().includes(deniedPath.toLowerCase())) {
      block("fs.deny_path", "high", 84, `Tool arguments reference denied path '${deniedPath}'.`);
    }
  }

  if (effective.rules?.filesystem?.warnOnAbsolutePaths && /(?:[A-Za-z]:[\\/]|\/(?:Users|home|etc|var|root)\b)/.test(serializedArguments)) {
    warn("fs.absolute_path", "Tool arguments reference an absolute filesystem path.");
  }

  for (const host of extractHosts(serializedArguments)) {
    if ((effective.rules?.network?.denyHosts ?? []).some((pattern) => matchesHost(host, pattern))) {
      block("network.denied_host", "high", 85, `Tool arguments reference denied host '${host}'.`);
    } else if ((effective.rules?.network?.warnHosts ?? []).some((pattern) => matchesHost(host, pattern))) {
      warn("network.warn_host", `Tool arguments reference watched host '${host}'.`);
    }
  }

  if (isDatabaseTool(toolName) || /\b(?:SELECT|UPDATE|DELETE|DROP|TRUNCATE)\b/i.test(serializedArguments)) {
    for (const rule of DESTRUCTIVE_SQL_PATTERNS) {
      if (rule.pattern.test(serializedArguments)) {
        block("db.destructive_query", "high", 82, rule.reason);
      }
    }
  }

  return {
    action: effective.mode === "monitor" && riskScore >= 75 ? "warn" : action,
    severity,
    riskScore,
    reasons,
    ruleIds
  };

  function warn(ruleId: string, reason: string): void {
    if (action === "allow") {
      action = "warn";
    }
    severity = maxSeverity(severity, "medium");
    riskScore = Math.max(riskScore, 40);
    reasons.push(reason);
    ruleIds.push(ruleId);
  }

  function block(ruleId: string, findingSeverity: Severity, score: number, reason: string): void {
    action = "block";
    severity = maxSeverity(severity, findingSeverity);
    riskScore = Math.max(riskScore, score);
    reasons.push(reason);
    ruleIds.push(ruleId);
  }
}

export function matchesGlob(value: string, pattern: string): boolean {
  return wildcardToRegExp(pattern).test(value);
}

function matchesAny(value: string, patterns: string[]): boolean {
  return patterns.some((pattern) => wildcardToRegExp(pattern).test(value));
}

function wildcardToRegExp(pattern: string): RegExp {
  const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".");
  return new RegExp(`^${escaped}$`, "i");
}

function extractCommand(toolCall: ToolCall): string | undefined {
  if (!SHELL_TOOL_NAMES.has(toolCall.name) && !/shell|exec|command/i.test(toolCall.name)) {
    return undefined;
  }
  const args = toolCall.arguments;
  if (typeof args === "string") {
    return args;
  }
  if (!args || typeof args !== "object") {
    return undefined;
  }
  const record = args as Record<string, unknown>;
  const command = record.command ?? record.cmd ?? record.script;
  if (typeof command !== "string") {
    return undefined;
  }

  const argList = Array.isArray(record.args) ? record.args.map((arg) => String(arg)) : [];
  return [command, ...argList].join(" ");
}

function isFilesystemTool(toolName: string): boolean {
  return /(?:file|fs|filesystem|read|write|edit|path|directory)/i.test(toolName);
}

function isDatabaseTool(toolName: string): boolean {
  return /(?:sql|database|postgres|mysql|sqlite|query|execute)/i.test(toolName);
}

function extractHosts(text: string): string[] {
  const hosts = new Set<string>();
  for (const match of text.matchAll(/\bhttps?:\/\/([^/\s"'<>]+)/gi)) {
    const host = match[1]?.toLowerCase().replace(/:\d+$/, "");
    if (host) {
      hosts.add(host);
    }
  }

  return [...hosts];
}

function matchesHost(host: string, pattern: string): boolean {
  const normalized = pattern.toLowerCase();
  return wildcardToRegExp(normalized).test(host) || host === normalized || host.endsWith(`.${normalized}`);
}

function safeStringify(value: unknown): string {
  try {
    return JSON.stringify(value) ?? "";
  } catch {
    return String(value);
  }
}

function maxSeverity(a: Severity, b: Severity): Severity {
  const rank: Record<Severity, number> = {
    info: 0,
    low: 1,
    medium: 2,
    high: 3,
    critical: 4
  };

  return rank[b] > rank[a] ? b : a;
}
