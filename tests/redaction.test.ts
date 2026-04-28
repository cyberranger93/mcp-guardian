import { describe, expect, it } from "vitest";
import { detectSecrets, redactText, redactValue } from "../src/redact.js";

describe("secret redaction", () => {
  it("redacts common token formats inside strings", () => {
    const value = "Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345";

    expect(redactText(value)).not.toContain("abcdefghijklmnopqrstuvwxyz012345");
  });

  it("redacts secret-like object keys recursively without mutating the input", () => {
    const input = {
      nested: {
        apiKey: "sk-proj-abcdefghijklmnopqrstuvwxyz",
        normal: "visible"
      }
    };

    const output = redactValue(input);

    expect(output).toEqual({
      nested: {
        apiKey: "[REDACTED]",
        normal: "visible"
      }
    });
    expect(input.nested.apiKey).toBe("sk-proj-abcdefghijklmnopqrstuvwxyz");
  });

  it("detects secrets in structured values", () => {
    expect(detectSecrets("OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz").length).toBeGreaterThan(0);
    expect(detectSecrets("LOG_LEVEL=debug")).toHaveLength(0);
  });
});
