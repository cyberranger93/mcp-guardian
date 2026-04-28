import type { JsonRpcMessage, ToolCall } from "./types.js";
import { redactValue } from "./redact.js";

export function parseJsonRpcMessage(input: string): JsonRpcMessage {
  const parsed = JSON.parse(input) as unknown;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("JSON-RPC message must be an object.");
  }
  const message = parsed as JsonRpcMessage;
  if (message.jsonrpc !== "2.0") {
    throw new Error("Unsupported JSON-RPC version.");
  }
  return message;
}

export function parseJsonRpcLine(line: string): JsonRpcMessage | undefined {
  const trimmed = line.trim();
  if (!trimmed) {
    return undefined;
  }
  return parseJsonRpcMessage(trimmed);
}

export function extractToolCall(message: JsonRpcMessage): ToolCall | undefined {
  if (message.method !== "tools/call") {
    return undefined;
  }
  if (!message.params || typeof message.params !== "object" || Array.isArray(message.params)) {
    return undefined;
  }
  const params = message.params as Record<string, unknown>;
  if (typeof params.name !== "string") {
    return undefined;
  }
  return {
    name: params.name,
    arguments: params.arguments ?? {}
  };
}

export function redactJsonRpcMessage(message: JsonRpcMessage): JsonRpcMessage {
  return redactValue(message) as JsonRpcMessage;
}

export function makeJsonRpcError(id: string | number | null, code: number, message: string): JsonRpcMessage {
  return {
    jsonrpc: "2.0",
    id,
    error: {
      code,
      message
    }
  };
}

export function blockResponse(request: JsonRpcMessage, message: string): JsonRpcMessage {
  return makeJsonRpcError(request.id ?? null, -32000, message);
}

export function serializeJsonRpc(message: JsonRpcMessage): string {
  return `${JSON.stringify(message)}\n`;
}
