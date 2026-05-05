export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type FirewallMode = 'allow' | 'deny' | 'audit';
export type OutputFormat = 'json' | 'table' | 'sarif';
export type FailThreshold = 'critical' | 'high' | 'medium';
export type ScanFinding = {
    id: string;
    severity: Severity;
    title: string;
    description: string;
    remediation: string;
    location?: string;
};
export type ScanReport = {
    server: string;
    timestamp: string;
    findings: ScanFinding[];
    passed: boolean;
    score: number;
};
export type FirewallDecision = {
    allowed: boolean;
    reason?: string;
    matchedRule?: string;
};
export type ToolCall = {
    toolName: string;
    args: Record<string, unknown>;
    context?: string;
};
export type MCPToolParameter = {
    name: string;
    type?: string;
    description?: string;
    required?: boolean;
};
export type MCPTool = {
    name: string;
    description?: string;
    parameters?: MCPToolParameter[];
    inputSchema?: Record<string, unknown>;
};
export type MCPPermissions = {
    filesystem?: {
        read?: string[];
        write?: string[];
    };
    network?: {
        allowedHosts?: string[];
        allowAllHosts?: boolean;
    };
    scopes?: string[];
};
export type MCPServerManifest = {
    name?: string;
    version?: string;
    description?: string;
    tools?: MCPTool[];
    permissions?: MCPPermissions;
    auth?: {
        required?: boolean;
        type?: string;
    };
};
export type FirewallRule = {
    id: string;
    name: string;
    description: string;
    severity: Severity;
    match: (call: ToolCall) => boolean;
};
export type PolicyRuleOverride = {
    ruleId: string;
    action: 'skip' | 'elevate' | 'downgrade';
};
export type Policy = {
    name: string;
    description: string;
    defaultMode: FirewallMode;
    rules?: PolicyRuleOverride[];
};
//# sourceMappingURL=types.d.ts.map