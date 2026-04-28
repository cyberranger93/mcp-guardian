import { detectSecrets, redactText, redactValue } from "./redact.js";

export function redactString(value: string): string {
  return redactText(value).replace(/\[REDACTED:\d+\]/g, "REDACTED");
}

export function redactSecrets<T>(value: T): T {
  return redactValue(value) as T;
}

export function containsSecret(value: unknown): boolean {
  const serialized = typeof value === "string" ? value : safeStringify(value);
  if (!serialized) {
    return false;
  }

  return detectSecrets(serialized).length > 0 || hasSensitiveKey(value);
}

function hasSensitiveKey(value: unknown): boolean {
  if (!value || typeof value !== "object") {
    return false;
  }

  for (const [key, child] of Object.entries(value)) {
    if (/(?:api[_-]?key|access[_-]?token|auth[_-]?token|authorization|bearer|credential|password|private[_-]?key|secret|session|token)/i.test(key)) {
      return true;
    }
    if (hasSensitiveKey(child)) {
      return true;
    }
  }

  return false;
}

function safeStringify(value: unknown): string {
  try {
    return JSON.stringify(value) ?? "";
  } catch {
    return "";
  }
}
