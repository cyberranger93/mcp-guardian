import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import type { GuardianConfig } from "./types.js";

export const DEFAULT_CONFIG: Required<GuardianConfig> = {
  version: "0.1",
  mode: "enforce",
  audit: {
    enabled: true,
    path: ".mcp-guardian/audit.jsonl",
    includeArguments: true,
    redact: true
  },
  redaction: {
    enabled: true,
    redactResponses: true
  },
  tools: {
    allow: [],
    deny: [
      "dangerously_*",
      "*unsafe*"
    ],
    warn: []
  },
  rules: {
    shell: {
      blockDangerousCommands: true,
      denyPatterns: [],
      warnPatterns: []
    },
    filesystem: {
      blockSensitiveReads: true,
      denyPaths: [],
      warnOnAbsolutePaths: false
    },
    network: {
      denyHosts: [],
      warnHosts: []
    },
    secrets: {
      blockOnSecret: true
    }
  },
  scanner: {
    maxFileSizeBytes: 1_000_000,
    exclude: [
      ".git",
      "node_modules",
      "dist",
      "coverage",
      ".next",
      ".turbo",
      ".mcp-guardian"
    ]
  }
};

const CONFIG_NAMES = [
  ".mcp-guardian.json",
  "mcp-guardian.config.json",
  "mcp-guardian.json"
];

export function resolveConfigPath(cwd = process.cwd(), explicitPath?: string): string | undefined {
  if (explicitPath) {
    return resolve(cwd, explicitPath);
  }

  if (process.env.MCP_GUARDIAN_CONFIG) {
    return resolve(cwd, process.env.MCP_GUARDIAN_CONFIG);
  }

  for (const name of CONFIG_NAMES) {
    const candidate = resolve(cwd, name);
    if (existsSync(candidate)) {
      return candidate;
    }
  }

  return undefined;
}

export function loadConfig(cwd = process.cwd(), explicitPath?: string): GuardianConfig {
  const configPath = resolveConfigPath(cwd, explicitPath);
  if (!configPath) {
    return DEFAULT_CONFIG;
  }

  const raw = readFileSync(configPath, "utf8");
  const parsed = JSON.parse(raw) as GuardianConfig;
  return mergeConfig(DEFAULT_CONFIG, parsed);
}

export function mergeConfig(base: GuardianConfig, override: GuardianConfig): GuardianConfig {
  return {
    ...base,
    ...override,
    audit: {
      ...base.audit,
      ...override.audit
    },
    redaction: {
      ...base.redaction,
      ...override.redaction
    },
    tools: {
      ...base.tools,
      ...override.tools
    },
    rules: {
      shell: {
        ...base.rules?.shell,
        ...override.rules?.shell
      },
      filesystem: {
        ...base.rules?.filesystem,
        ...override.rules?.filesystem
      },
      network: {
        ...base.rules?.network,
        ...override.rules?.network
      },
      secrets: {
        ...base.rules?.secrets,
        ...override.rules?.secrets
      }
    },
    scanner: {
      ...base.scanner,
      ...override.scanner
    }
  };
}

export function sampleConfig(): GuardianConfig {
  return {
    version: "0.1",
    mode: "enforce",
    audit: {
      enabled: true,
      path: ".mcp-guardian/audit.jsonl",
      includeArguments: true,
      redact: true
    },
    redaction: {
      enabled: true,
      redactResponses: true
    },
    tools: {
      allow: [],
      deny: [
        "shell",
        "exec",
        "dangerously_*",
        "*unsafe*"
      ],
      warn: [
        "browser_*",
        "http_*"
      ]
    },
    rules: {
      shell: {
        blockDangerousCommands: true,
        denyPatterns: [
          "curl.+\\|\\s*(sh|bash|pwsh|powershell)",
          "Invoke-WebRequest.+\\|",
          "git\\s+reset\\s+--hard",
          "rm\\s+-rf\\s+(/|\\*)"
        ],
        warnPatterns: [
          "npm\\s+install",
          "pip\\s+install",
          "docker\\s+run"
        ]
      },
      filesystem: {
        blockSensitiveReads: true,
        denyPaths: [
          ".env",
          ".aws/credentials",
          ".ssh/id_rsa",
          ".ssh/id_ed25519"
        ],
        warnOnAbsolutePaths: true
      },
      network: {
        denyHosts: [],
        warnHosts: [
          "pastebin.com",
          "webhook.site"
        ]
      },
      secrets: {
        blockOnSecret: true
      }
    }
  };
}
