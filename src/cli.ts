#!/usr/bin/env node
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { basename, dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { loadConfig, sampleConfig } from "./config.js";
import { evaluatePolicy } from "./policy.js";
import { redactValue } from "./redact.js";
import { formatGithubAnnotations, formatSummary, scanPath, shouldFail, toSarif } from "./scanner.js";
import { runProxy } from "./proxy.js";
import type { Severity } from "./types.js";

interface ParsedArgs {
  command: string | undefined;
  positionals: string[];
  flags: Record<string, string | boolean>;
}

export const VERSION = "0.1.3";

export async function main(argv = process.argv.slice(2)): Promise<void> {
  const parsed = parseArgs(argv);

  if (parsed.flags.version === true || parsed.flags.v === true) {
    process.stdout.write(`${VERSION}\n`);
    return;
  }

  if (!parsed.command || parsed.flags.help === true || parsed.flags.h === true) {
    printHelp();
    return;
  }

  switch (parsed.command) {
    case "init":
      initConfig(parsed);
      break;
    case "scan":
      scanCommand(parsed);
      break;
    case "proxy":
      await proxyCommand(parsed);
      break;
    case "eval":
      evalCommand(parsed);
      break;
    case "redact":
      redactCommand(parsed);
      break;
    default:
      fail(`unknown command: ${parsed.command}`);
  }
}

function initConfig(parsed: ParsedArgs): void {
  const output = String(parsed.flags.output ?? parsed.flags.o ?? ".mcp-guardian.json");
  const path = resolve(process.cwd(), output);
  if (existsSync(path) && parsed.flags.force !== true) {
    fail(`${output} already exists. Use --force to overwrite.`);
  }

  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(sampleConfig(), null, 2)}\n`, "utf8");
  process.stdout.write(`Created ${output}\n`);
}

function scanCommand(parsed: ParsedArgs): void {
  const target = resolve(process.cwd(), parsed.positionals[0] ?? ".");
  if (!existsSync(target)) {
    fail(`scan target does not exist: ${target}`);
  }

  const config = loadConfig(process.cwd(), stringFlag(parsed, "config"));
  const summary = scanPath({ root: target, config });
  const format = String(parsed.flags.format ?? "text");

  if (format === "json") {
    process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
  } else if (format === "github") {
    const annotations = formatGithubAnnotations(summary);
    if (annotations) {
      process.stdout.write(`${annotations}\n`);
    }
    process.stdout.write(`${formatSummary(summary)}\n`);
  } else if (format === "sarif") {
    process.stdout.write(`${toSarif(summary)}\n`);
  } else {
    process.stdout.write(`${formatSummary(summary)}\n`);
  }

  const failOn = parseSeverity(String(parsed.flags["fail-on"] ?? "critical"));
  if (shouldFail(summary, failOn)) {
    process.exitCode = 1;
  }
}

async function proxyCommand(parsed: ParsedArgs): Promise<void> {
  const separatorIndex = parsed.positionals.indexOf("--");
  const commandParts = separatorIndex >= 0 ? parsed.positionals.slice(separatorIndex + 1) : parsed.positionals;
  const command = commandParts[0];
  if (!command) {
    fail("proxy requires a server command. Example: mcp-guardian proxy -- node server.js");
  }

  const config = loadConfig(process.cwd(), stringFlag(parsed, "config"));
  const exitCode = await runProxy({
    config,
    command,
    args: commandParts.slice(1),
    cwd: process.cwd()
  });
  process.exitCode = exitCode;
}

function evalCommand(parsed: ParsedArgs): void {
  const tool = String(parsed.flags.tool ?? parsed.positionals[0] ?? "");
  if (!tool) {
    fail("eval requires --tool <name>");
  }

  const argsText = String(parsed.flags.arguments ?? parsed.flags.args ?? parsed.positionals[1] ?? "{}");
  const args = JSON.parse(argsText) as unknown;
  const config = loadConfig(process.cwd(), stringFlag(parsed, "config"));
  const decision = evaluatePolicy({
    name: tool,
    arguments: args
  }, config);

  process.stdout.write(`${JSON.stringify(decision, null, 2)}\n`);
  if (decision.action === "block") {
    process.exitCode = 2;
  }
}

function redactCommand(parsed: ParsedArgs): void {
  const input = parsed.positionals.join(" ");
  if (!input) {
    fail("redact requires input text");
  }

  process.stdout.write(`${JSON.stringify(redactValue(input))}\n`);
}

export function parseArgs(args: string[]): ParsedArgs {
  const firstArg = args[0];
  const result: ParsedArgs = {
    command: firstArg && !firstArg.startsWith("-") ? firstArg : undefined,
    positionals: [],
    flags: {}
  };

  const startIndex = result.command ? 1 : 0;
  for (let index = startIndex; index < args.length; index += 1) {
    const arg = args[index];
    if (!arg) {
      continue;
    }

    if (arg === "--") {
      result.positionals.push("--", ...args.slice(index + 1));
      break;
    }

    if (arg.startsWith("--")) {
      const [key, inlineValue] = arg.slice(2).split("=", 2);
      if (!key) {
        continue;
      }
      if (inlineValue !== undefined) {
        result.flags[key] = inlineValue;
      } else if (args[index + 1] && !args[index + 1]!.startsWith("-")) {
        result.flags[key] = args[index + 1]!;
        index += 1;
      } else {
        result.flags[key] = true;
      }
      continue;
    }

    if (arg.startsWith("-") && arg.length > 1) {
      const key = arg.slice(1);
      if (args[index + 1] && !args[index + 1]!.startsWith("-")) {
        result.flags[key] = args[index + 1]!;
        index += 1;
      } else {
        result.flags[key] = true;
      }
      continue;
    }

    result.positionals.push(arg);
  }

  return result;
}

function stringFlag(parsed: ParsedArgs, name: string): string | undefined {
  const value = parsed.flags[name];
  return typeof value === "string" ? value : undefined;
}

function parseSeverity(value: string): Severity {
  if (["info", "low", "medium", "high", "critical"].includes(value)) {
    return value as Severity;
  }

  fail(`invalid severity '${value}'. Use info, low, medium, high, or critical.`);
}

function printHelp(): void {
  process.stdout.write(`mcp-guardian ${VERSION}

A local security firewall, scanner, and audit layer for MCP servers.

Usage:
  mcp-guardian init [--output .mcp-guardian.json] [--force]
  mcp-guardian scan [path] [--config file] [--fail-on critical] [--format text|json|github|sarif]
  mcp-guardian proxy [--config file] -- <server-command> [...args]
  mcp-guardian eval --tool <name> --arguments '{"command":"rm -rf /"}'
  mcp-guardian redact "text containing a token"

Examples:
  mcp-guardian init
  mcp-guardian scan . --fail-on high
  mcp-guardian proxy -- npx -y @modelcontextprotocol/server-filesystem .
`);
}

function fail(message: string): never {
  process.stderr.write(`mcp-guardian: ${message}\n`);
  process.exit(1);
}

if (isCliEntrypoint()) {
  main().catch((error) => {
    process.stderr.write(`mcp-guardian: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exit(1);
  });
}

function isCliEntrypoint(): boolean {
  const invokedPath = process.argv[1];
  if (!invokedPath) {
    return false;
  }

  const currentPath = fileURLToPath(import.meta.url);
  return import.meta.url === pathToFileURL(resolve(invokedPath)).href || basename(currentPath) === basename(invokedPath);
}
