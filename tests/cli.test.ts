import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { parseArgs, VERSION } from "../src/cli.js";

describe("CLI argument parsing", () => {
  it("keeps the CLI version aligned with package.json", () => {
    const packageJson = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };

    expect(VERSION).toBe(packageJson.version);
  });

  it("treats global --help as a flag instead of an unknown command", () => {
    expect(parseArgs(["--help"])).toEqual({
      command: undefined,
      positionals: [],
      flags: {
        help: true
      }
    });
  });

  it("parses command flags and positionals", () => {
    expect(parseArgs(["scan", ".", "--fail-on", "high"])).toEqual({
      command: "scan",
      positionals: ["."],
      flags: {
        "fail-on": "high"
      }
    });
  });

  it("preserves proxy command arguments after --", () => {
    expect(parseArgs(["proxy", "--", "node", "server.js"])).toEqual({
      command: "proxy",
      positionals: ["--", "node", "server.js"],
      flags: {}
    });
  });
});
