import { mkdirSync, appendFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import type { AuditEvent, GuardianConfig } from "./types.js";
import { redactValue } from "./redact.js";

export class AuditLogger {
  private readonly enabled: boolean;
  private readonly path: string;
  private readonly includeArguments: boolean;
  private readonly shouldRedact: boolean;

  constructor(config: GuardianConfig, cwd = process.cwd()) {
    this.enabled = config.audit?.enabled !== false;
    this.path = resolve(cwd, config.audit?.path ?? ".mcp-guardian/audit.jsonl");
    this.includeArguments = config.audit?.includeArguments !== false;
    this.shouldRedact = config.audit?.redact !== false;
  }

  write(event: Omit<AuditEvent, "timestamp" | "pid">): void {
    if (!this.enabled) {
      return;
    }

    mkdirSync(dirname(this.path), { recursive: true });
    const fullEvent: AuditEvent = {
      timestamp: new Date().toISOString(),
      pid: process.pid,
      ...event
    };

    if (!this.includeArguments) {
      delete fullEvent.arguments;
    }

    const output = this.shouldRedact ? redactValue(fullEvent) : fullEvent;
    appendFileSync(this.path, `${JSON.stringify(output)}\n`, "utf8");
  }
}
