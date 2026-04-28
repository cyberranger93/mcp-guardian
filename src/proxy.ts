import type { Readable } from "node:stream";
import { AuditLogger } from "./audit.js";
import type { GuardianConfig, JsonRpcMessage } from "./types.js";
import { evaluatePolicy } from "./policy.js";
import { redactValue } from "./redact.js";
import { blockResponse, extractToolCall, parseJsonRpcLine, serializeJsonRpc } from "./jsonrpc.js";
import { spawnSafe } from "./process.js";

export interface ProxyOptions {
  config: GuardianConfig;
  command: string;
  args: string[];
  cwd?: string;
}

export async function runProxy(options: ProxyOptions): Promise<number> {
  const audit = new AuditLogger(options.config, options.cwd ?? process.cwd());

  audit.write({
    direction: "guardian",
    message: `starting MCP server: ${options.command} ${options.args.join(" ")}`
  });

  const spawnRequest = {
    command: options.command,
    args: options.args,
    env: process.env
  };
  const child = spawnSafe(options.cwd === undefined ? spawnRequest : { ...spawnRequest, cwd: options.cwd });

  child.on("error", (error) => {
    audit.write({
      direction: "guardian",
      message: `failed to start MCP server: ${error.message}`
    });
    process.stderr.write(`[mcp-guardian] failed to start server: ${error.message}\n`);
  });

  child.stderr?.on("data", (chunk: Buffer) => {
    process.stderr.write(chunk);
  });

  pumpLines(process.stdin, (line) => {
    const handled = handleClientLine(line, child.stdin, audit, options.config);
    if (!handled) {
      child.stdin?.write(line);
    }
  });

  if (child.stdout) {
    pumpLines(child.stdout, (line) => {
      const outbound = handleServerLine(line, audit, options.config);
      process.stdout.write(outbound);
    });
  }

  process.on("SIGINT", () => child.kill("SIGINT"));
  process.on("SIGTERM", () => child.kill("SIGTERM"));

  const exitCode = await new Promise<number>((resolve) => {
    child.on("close", (code) => resolve(code ?? 0));
  });

  audit.write({
    direction: "guardian",
    message: `MCP server exited with code ${exitCode}`
  });

  return exitCode;
}

function handleClientLine(line: string, childStdin: NodeJS.WritableStream | null, audit: AuditLogger, config: GuardianConfig): boolean {
  let message: JsonRpcMessage | undefined;
  try {
    message = parseJsonRpcLine(line);
  } catch (error) {
    audit.write({
      direction: "client_to_server",
      message: `could not parse JSON-RPC line: ${error instanceof Error ? error.message : "invalid JSON"}`
    });
    return false;
  }

  if (!message) {
    return false;
  }

  const toolCall = extractToolCall(message);
  if (!toolCall) {
    audit.write({
      direction: "client_to_server",
      ...optionalRpcFields(message)
    });
    return false;
  }

  const decision = evaluatePolicy(toolCall, config);
  audit.write({
    direction: "client_to_server",
    ...optionalRpcFields(message),
    toolName: toolCall.name,
    decision,
    arguments: toolCall.arguments
  });

  if (decision.action === "block") {
    process.stdout.write(serializeJsonRpc(blockResponse(message, decision.reasons.join("; "))));
    return true;
  }

  childStdin?.write(line);
  return true;
}

function handleServerLine(line: string, audit: AuditLogger, config: GuardianConfig): string {
  let message: JsonRpcMessage | undefined;
  try {
    message = parseJsonRpcLine(line);
  } catch {
    return line;
  }

  if (!message) {
    return line;
  }

  audit.write({
    direction: "server_to_client",
    ...optionalRpcFields(message),
    redacted: config.redaction?.redactResponses !== false
  });

  if (config.redaction?.enabled === false || config.redaction?.redactResponses === false) {
    return line;
  }

  return serializeJsonRpc(redactValue(message) as JsonRpcMessage);
}

function optionalRpcFields(message: JsonRpcMessage): Pick<JsonRpcMessage, "method" | "id"> {
  const fields: Pick<JsonRpcMessage, "method" | "id"> = {};
  if (message.method !== undefined) {
    fields.method = message.method;
  }
  if (message.id !== undefined) {
    fields.id = message.id;
  }
  return fields;
}

function pumpLines(stream: Readable, onLine: (line: string) => void): void {
  let buffer = "";
  stream.on("data", (chunk: Buffer | string) => {
    buffer += chunk.toString();
    let newlineIndex = buffer.indexOf("\n");
    while (newlineIndex >= 0) {
      const line = buffer.slice(0, newlineIndex + 1);
      buffer = buffer.slice(newlineIndex + 1);
      onLine(line);
      newlineIndex = buffer.indexOf("\n");
    }
  });

  stream.on("end", () => {
    if (buffer.length > 0) {
      onLine(buffer.endsWith("\n") ? buffer : `${buffer}\n`);
    }
  });
}
