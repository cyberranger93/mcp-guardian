export type Severity = "info" | "low" | "medium" | "high" | "critical";

export type GuardianMode = "enforce" | "monitor";

export interface GuardianConfig {
  version?: string;
  mode?: GuardianMode;
  audit?: {
    enabled?: boolean;
    path?: string;
    includeArguments?: boolean;
    redact?: boolean;
  };
  redaction?: {
    enabled?: boolean;
    redactResponses?: boolean;
  };
  tools?: {
    allow?: string[];
    deny?: string[];
    warn?: string[];
  };
  rules?: {
    shell?: {
      blockDangerousCommands?: boolean;
      denyPatterns?: string[];
      warnPatterns?: string[];
    };
    filesystem?: {
      blockSensitiveReads?: boolean;
      denyPaths?: string[];
      warnOnAbsolutePaths?: boolean;
    };
    network?: {
      denyHosts?: string[];
      warnHosts?: string[];
    };
    secrets?: {
      blockOnSecret?: boolean;
    };
  };
  scanner?: {
    maxFileSizeBytes?: number;
    exclude?: string[];
  };
}

export interface ToolCall {
  name: string;
  arguments: unknown;
}

export interface PolicyDecision {
  action: "allow" | "warn" | "block";
  severity: Severity;
  riskScore: number;
  reasons: string[];
  ruleIds: string[];
}

export interface JsonRpcMessage {
  jsonrpc?: string;
  id?: string | number | null;
  method?: string;
  params?: unknown;
  result?: unknown;
  error?: unknown;
  [key: string]: unknown;
}

export interface AuditEvent {
  timestamp: string;
  pid: number;
  direction: "client_to_server" | "server_to_client" | "guardian";
  method?: string;
  id?: string | number | null;
  toolName?: string;
  decision?: PolicyDecision;
  arguments?: unknown;
  redacted?: boolean;
  message?: string;
}

export interface ScanFinding {
  file: string;
  line?: number;
  column?: number;
  severity: Severity;
  type: string;
  message: string;
  evidence?: string;
}

export interface ScanSummary {
  scannedFiles: number;
  findings: ScanFinding[];
  counts: Record<Severity, number>;
}
