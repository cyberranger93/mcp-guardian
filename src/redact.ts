import type { ScanFinding } from "./types.js";

export interface SecretPattern {
  id: string;
  severity: ScanFinding["severity"];
  pattern: RegExp;
  message: string;
}

export const SECRET_PATTERNS: SecretPattern[] = [
  {
    id: "secret.openai",
    severity: "critical",
    pattern: /\bsk-[A-Za-z0-9_-]{20,}\b/g,
    message: "OpenAI-style API key"
  },
  {
    id: "secret.anthropic",
    severity: "critical",
    pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g,
    message: "Anthropic API key"
  },
  {
    id: "secret.github",
    severity: "critical",
    pattern: /\bgh[pousr]_[A-Za-z0-9_]{30,255}\b/g,
    message: "GitHub token"
  },
  {
    id: "secret.aws_access_key",
    severity: "high",
    pattern: /\b(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ASIA)[A-Z0-9]{16}\b/g,
    message: "AWS access key ID"
  },
  {
    id: "secret.slack",
    severity: "high",
    pattern: /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/g,
    message: "Slack token"
  },
  {
    id: "secret.private_key",
    severity: "critical",
    pattern: /-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/g,
    message: "Private key material"
  },
  {
    id: "secret.connection_string",
    severity: "high",
    pattern: /\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis):\/\/[^"'\s<>]+/gi,
    message: "Database or cache connection string"
  },
  {
    id: "secret.jwt",
    severity: "medium",
    pattern: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
    message: "JWT-like token"
  },
  {
    id: "secret.generic_assignment",
    severity: "medium",
    pattern: /\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|secret|password|client[_-]?secret)\b\s*[:=]\s*["']?([A-Za-z0-9_./+=:-]{12,})/gi,
    message: "Generic secret assignment"
  }
];

const SENSITIVE_KEY = /(?:api[_-]?key|access[_-]?token|auth[_-]?token|bearer|credential|password|private[_-]?key|secret|session|token)/i;

export function detectSecrets(text: string): ScanFinding[] {
  const findings: ScanFinding[] = [];

  for (const secretPattern of SECRET_PATTERNS) {
    for (const match of text.matchAll(secretPattern.pattern)) {
      if (match.index === undefined) {
        continue;
      }

      findings.push({
        file: "",
        severity: secretPattern.severity,
        type: secretPattern.id,
        message: secretPattern.message,
        evidence: maskSecret(match[0])
      });
    }
  }

  return findings;
}

export function redactText(text: string): string {
  let redacted = text;
  for (const secretPattern of SECRET_PATTERNS) {
    redacted = redacted.replace(secretPattern.pattern, (match) => maskSecret(match));
  }

  redacted = redacted.replace(
    /\b(Authorization\s*:\s*Bearer\s+)([A-Za-z0-9._~+/=-]{12,})/gi,
    (_match, prefix: string, secret: string) => `${prefix}${maskSecret(secret)}`
  );

  return redacted;
}

export function redactValue(value: unknown, depth = 0): unknown {
  if (depth > 12) {
    return "[REDACTED:MAX_DEPTH]";
  }

  if (typeof value === "string") {
    return redactText(value);
  }

  if (Array.isArray(value)) {
    return value.map((item) => redactValue(item, depth + 1));
  }

  if (value && typeof value === "object") {
    const output: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(value)) {
      if (SENSITIVE_KEY.test(key)) {
        output[key] = "[REDACTED]";
      } else {
        output[key] = redactValue(child, depth + 1);
      }
    }
    return output;
  }

  return value;
}

export function maskSecret(secret: string): string {
  if (secret.length <= 8) {
    return "[REDACTED]";
  }

  const prefix = secret.slice(0, 4);
  const suffix = secret.slice(-4);
  return `${prefix}...[REDACTED:${secret.length}]...${suffix}`;
}
