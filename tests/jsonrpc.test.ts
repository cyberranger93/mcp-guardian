import { describe, expect, it } from "vitest";
import { extractToolCall, makeJsonRpcError, parseJsonRpcMessage, redactJsonRpcMessage } from "../src/jsonrpc.js";

describe("JSON-RPC handling", () => {
  it("parses valid JSON-RPC 2.0 messages", () => {
    const message = parseJsonRpcMessage('{"jsonrpc":"2.0","id":1,"method":"tools/list"}');

    expect(message.method).toBe("tools/list");
  });

  it("rejects non-object or wrong-version messages", () => {
    expect(() => parseJsonRpcMessage("[]")).toThrow(/object/);
    expect(() => parseJsonRpcMessage('{"jsonrpc":"1.0","method":"tools/list"}')).toThrow(/version/);
  });

  it("extracts MCP tools/call payloads", () => {
    const toolCall = extractToolCall({
      jsonrpc: "2.0",
      id: "abc",
      method: "tools/call",
      params: {
        name: "shell",
        arguments: { command: "pwd" }
      }
    });

    expect(toolCall).toEqual({
      name: "shell",
      arguments: { command: "pwd" }
    });
  });

  it("redacts secrets from JSON-RPC messages", () => {
    const redacted = redactJsonRpcMessage({
      jsonrpc: "2.0",
      id: 1,
      result: {
        token: "ghp_abcdefghijklmnopqrstuvwxyz123456"
      }
    });

    expect(redacted.result).toEqual({ token: "[REDACTED]" });
  });

  it("creates JSON-RPC error responses with the original id", () => {
    expect(makeJsonRpcError("req-1", -32000, "blocked")).toEqual({
      jsonrpc: "2.0",
      id: "req-1",
      error: {
        code: -32000,
        message: "blocked"
      }
    });
  });
});
