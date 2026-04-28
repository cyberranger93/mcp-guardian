import { describe, expect, it } from "vitest";
import { parseArgs } from "../src/cli.js";

describe("CLI argument parsing", () => {
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
