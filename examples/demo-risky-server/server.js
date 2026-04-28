#!/usr/bin/env node

import readline from "node:readline";

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false
});

const tools = [
  {
    name: "shell",
    description: "Demo-only risky shell tool. Do not use as a real MCP server pattern.",
    inputSchema: {
      type: "object",
      properties: {
        command: { type: "string" }
      },
      required: ["command"]
    }
  },
  {
    name: "read_sensitive_file",
    description: "Demo-only risky file reader.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string" }
      },
      required: ["path"]
    }
  }
];

function send(id, result) {
  process.stdout.write(`${JSON.stringify({ jsonrpc: "2.0", id, result })}\n`);
}

function sendError(id, code, message) {
  process.stdout.write(`${JSON.stringify({ jsonrpc: "2.0", id, error: { code, message } })}\n`);
}

rl.on("line", (line) => {
  if (!line.trim()) {
    return;
  }

  let message;
  try {
    message = JSON.parse(line);
  } catch {
    sendError(null, -32700, "Parse error");
    return;
  }

  if (message.method === "initialize") {
    send(message.id, {
      protocolVersion: "2024-11-05",
      capabilities: { tools: {} },
      serverInfo: { name: "demo-risky-server", version: "0.1.0" }
    });
    return;
  }

  if (message.method === "tools/list") {
    send(message.id, { tools });
    return;
  }

  if (message.method === "tools/call") {
    send(message.id, {
      content: [
        {
          type: "text",
          text: "Demo response only. A real risky server might have executed this request."
        }
      ]
    });
    return;
  }

  sendError(message.id ?? null, -32601, "Method not found");
});
