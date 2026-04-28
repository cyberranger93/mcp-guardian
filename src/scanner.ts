import { lstatSync, readdirSync, readFileSync, statSync } from "node:fs";
import { basename, join, relative } from "node:path";
import type { GuardianConfig, ScanFinding, ScanSummary, Severity } from "./types.js";
import { detectSecrets, redactText } from "./redact.js";
import { evaluatePolicy } from "./policy.js";

const MCP_CONFIG_NAMES = new Set([
  ".mcp.json",
  "mcp.json",
  "mcp-servers.json",
  "claude_desktop_config.json",
  "claude_desktop_config.json.backup"
]);

const TEXT_FILE_EXTENSIONS = new Set([
  ".cjs",
  ".conf",
  ".config",
  ".env",
  ".ini",
  ".js",
  ".json",
  ".jsonc",
  ".lock",
  ".md",
  ".mjs",
  ".ps1",
  ".py",
  ".sh",
  ".toml",
  ".ts",
  ".tsx",
  ".txt",
  ".yaml",
  ".yml"
]);

const SEVERITIES: Severity[] = ["info", "low", "medium", "high", "critical"];

export interface ScanOptions {
  root: string;
  config: GuardianConfig;
}

export function scanPath(options: ScanOptions): ScanSummary {
  const findings: ScanFinding[] = [];
  let scannedFiles = 0;

  for (const filePath of walkFiles(options.root, options.config)) {
    const stat = statSync(filePath);
    const maxSize = options.config.scanner?.maxFileSizeBytes ?? 1_000_000;

    if (stat.size > maxSize || !isLikelyTextFile(filePath)) {
      continue;
    }

    const buffer = readFileSync(filePath);
    if (buffer.includes(0)) {
      continue;
    }

    scannedFiles += 1;
    const text = buffer.toString("utf8");
    const displayFile = normalizePath(relative(options.root, filePath) || basename(filePath));

    findings.push(...scanSecrets(displayFile, text));

    if (isMcpConfigFile(filePath, text)) {
      findings.push(...scanMcpConfig(displayFile, text, options.config));
    }
  }

  return {
    scannedFiles,
    findings: findings.sort(compareFindings),
    counts: countBySeverity(findings)
  };
}

export function formatSummary(summary: ScanSummary): string {
  const lines: string[] = [];
  lines.push(`MCP Guardian scanned ${summary.scannedFiles} files.`);
  lines.push(
    `Findings: critical=${summary.counts.critical}, high=${summary.counts.high}, medium=${summary.counts.medium}, low=${summary.counts.low}, info=${summary.counts.info}`
  );

  if (summary.findings.length === 0) {
    lines.push("No risky MCP configuration or secret material was detected.");
    return lines.join("\n");
  }

  for (const finding of summary.findings) {
    const location = finding.line ? `${finding.file}:${finding.line}` : finding.file;
    const evidence = finding.evidence ? ` (${finding.evidence})` : "";
    lines.push(`[${finding.severity.toUpperCase()}] ${location} ${finding.type}: ${finding.message}${evidence}`);
  }

  return lines.join("\n");
}

export function formatGithubAnnotations(summary: ScanSummary): string {
  return summary.findings
    .map((finding) => {
      const level = finding.severity === "critical" || finding.severity === "high" ? "error" : "warning";
      const file = escapeAnnotation(finding.file);
      const line = finding.line ? `,line=${finding.line}` : "";
      const col = finding.column ? `,col=${finding.column}` : "";
      const message = escapeAnnotation(`${finding.type}: ${finding.message}${finding.evidence ? ` (${finding.evidence})` : ""}`);
      return `::${level} file=${file}${line}${col}::${message}`;
    })
    .join("\n");
}

export function toSarif(summary: ScanSummary): string {
  const rules = new Map<string, { id: string; shortDescription: { text: string } }>();
  const results = summary.findings.map((finding) => {
    if (!rules.has(finding.type)) {
      rules.set(finding.type, {
        id: finding.type,
        shortDescription: {
          text: finding.message
        }
      });
    }

    return {
      ruleId: finding.type,
      level: sarifLevel(finding.severity),
      message: {
        text: finding.message
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: finding.file
            },
            region: {
              startLine: finding.line ?? 1,
              startColumn: finding.column ?? 1
            }
          }
        }
      ]
    };
  });

  return JSON.stringify(
    {
      version: "2.1.0",
      $schema: "https://json.schemastore.org/sarif-2.1.0.json",
      runs: [
        {
          tool: {
            driver: {
              name: "MCP Guardian",
              informationUri: "https://github.com/cyberranger93/mcp-guardian",
              rules: [...rules.values()]
            }
          },
          results
        }
      ]
    },
    null,
    2
  );
}

export function shouldFail(summary: ScanSummary, failOn: Severity): boolean {
  const threshold = severityRank(failOn);
  return summary.findings.some((finding) => severityRank(finding.severity) >= threshold);
}

function* walkFiles(root: string, config: GuardianConfig): Generator<string> {
  const exclude = config.scanner?.exclude ?? [];
  const entries = readdirSync(root, { withFileTypes: true });

  for (const entry of entries) {
    const path = join(root, entry.name);
    const normalized = normalizePath(path);

    if (exclude.some((pattern) => normalized.includes(pattern))) {
      continue;
    }

    if (entry.isSymbolicLink()) {
      continue;
    }

    if (entry.isDirectory()) {
      yield* walkFiles(path, config);
      continue;
    }

    if (entry.isFile() && lstatSync(path).isFile()) {
      yield path;
    }
  }
}

function scanSecrets(file: string, text: string): ScanFinding[] {
  const findings: ScanFinding[] = [];

  for (const finding of detectSecrets(text)) {
    const index = finding.evidence ? text.indexOf(finding.evidence.slice(0, 4)) : -1;
    const location = index >= 0 ? offsetToLocation(text, index) : undefined;
    findings.push({
      ...finding,
      file,
      ...(location ?? {})
    });
  }

  return findings;
}

function scanMcpConfig(file: string, text: string, config: GuardianConfig): ScanFinding[] {
  const findings: ScanFinding[] = [];
  let parsed: unknown;

  try {
    parsed = JSON.parse(stripJsonComments(text));
  } catch (error) {
    findings.push({
      file,
      severity: "medium",
      type: "mcp_config.invalid_json",
      message: `MCP configuration could not be parsed: ${error instanceof Error ? error.message : "invalid JSON"}`
    });
    return findings;
  }

  const servers = discoverMcpServers(parsed);
  for (const server of servers) {
    const command = server.command;
    const args = server.args;
    const env = server.env;

    if (typeof command === "string") {
      const decision = evaluatePolicy({
        name: "shell",
        arguments: {
          command,
          args
        }
      }, config);

      if (decision.action === "block") {
        findings.push({
          file,
          severity: decision.severity,
          type: "mcp_config.risky_server_command",
          message: `MCP server '${server.name}' command would be blocked by policy: ${decision.reasons.join("; ")}`,
          evidence: redactText([command, ...(Array.isArray(args) ? args : [])].join(" "))
        });
      } else if (decision.action === "warn") {
        findings.push({
          file,
          severity: "medium",
          type: "mcp_config.watched_server_command",
          message: `MCP server '${server.name}' command matches watched behavior: ${decision.reasons.join("; ")}`,
          evidence: redactText([command, ...(Array.isArray(args) ? args : [])].join(" "))
        });
      }

      if (/(?:npx|uvx|pipx|curl|wget|docker)\b/i.test(command) || (Array.isArray(args) && args.some((arg) => /(?:--privileged|--cap-add|latest|http:)/i.test(String(arg))))) {
        findings.push({
          file,
          severity: "medium",
          type: "mcp_config.supply_chain_surface",
          message: `MCP server '${server.name}' starts through a dynamic package, container, or network command`,
          evidence: redactText([command, ...(Array.isArray(args) ? args : [])].join(" "))
        });
      }
    }

    if (env && typeof env === "object") {
      for (const [key, value] of Object.entries(env)) {
        const valueText = typeof value === "string" ? value : JSON.stringify(value);
        if (detectSecrets(`${key}=${valueText}`).length > 0) {
          findings.push({
            file,
            severity: "critical",
            type: "mcp_config.inline_secret",
            message: `MCP server '${server.name}' embeds secret-like environment value '${key}'`,
            evidence: `${key}=${redactText(String(valueText))}`
          });
        }
      }
    }
  }

  return findings;
}

interface DiscoveredServer {
  name: string;
  command?: unknown;
  args?: unknown;
  env?: unknown;
}

function discoverMcpServers(value: unknown): DiscoveredServer[] {
  const root = value && typeof value === "object" ? (value as Record<string, unknown>) : {};
  const serverMap = (root.mcpServers ?? root.servers) as unknown;

  if (!serverMap || typeof serverMap !== "object" || Array.isArray(serverMap)) {
    return [];
  }

  return Object.entries(serverMap as Record<string, unknown>).map(([name, server]) => {
    const serverObject = server && typeof server === "object" ? (server as Record<string, unknown>) : {};
    return {
      name,
      command: serverObject.command,
      args: serverObject.args,
      env: serverObject.env
    };
  });
}

function countBySeverity(findings: ScanFinding[]): Record<Severity, number> {
  const counts = {
    info: 0,
    low: 0,
    medium: 0,
    high: 0,
    critical: 0
  };

  for (const finding of findings) {
    counts[finding.severity] += 1;
  }

  return counts;
}

function isMcpConfigFile(filePath: string, text: string): boolean {
  const name = basename(filePath);
  return MCP_CONFIG_NAMES.has(name) || (name.toLowerCase().includes("mcp") && text.includes("mcpServers"));
}

function isLikelyTextFile(filePath: string): boolean {
  const name = basename(filePath).toLowerCase();
  if (name.startsWith(".env") || name.includes("mcp") || name.includes("claude")) {
    return true;
  }

  const dot = name.lastIndexOf(".");
  if (dot < 0) {
    return false;
  }

  return TEXT_FILE_EXTENSIONS.has(name.slice(dot));
}

function stripJsonComments(text: string): string {
  return text
    .replace(/^\s*\/\/.*$/gm, "")
    .replace(/\/\*[\s\S]*?\*\//g, "");
}

function offsetToLocation(text: string, offset: number): { line: number; column: number } {
  const prefix = text.slice(0, offset);
  const lines = prefix.split(/\r?\n/);
  return {
    line: lines.length,
    column: (lines.at(-1)?.length ?? 0) + 1
  };
}

function compareFindings(a: ScanFinding, b: ScanFinding): number {
  return severityRank(b.severity) - severityRank(a.severity) || a.file.localeCompare(b.file) || (a.line ?? 0) - (b.line ?? 0);
}

function sarifLevel(severity: Severity): "none" | "note" | "warning" | "error" {
  if (severity === "critical" || severity === "high") {
    return "error";
  }
  if (severity === "medium" || severity === "low") {
    return "warning";
  }
  return "note";
}

function severityRank(severity: Severity): number {
  return SEVERITIES.indexOf(severity);
}

function normalizePath(path: string): string {
  return path.replace(/\\/g, "/");
}

function escapeAnnotation(value: string): string {
  return value.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A").replace(/:/g, "%3A").replace(/,/g, "%2C");
}
