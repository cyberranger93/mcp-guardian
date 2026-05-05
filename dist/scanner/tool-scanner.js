// Common safe tool names that could be shadowed
const SAFE_TOOL_NAMES = new Set([
    'read_file',
    'write_file',
    'search',
    'get',
    'list',
    'create',
    'delete',
    'update',
    'execute',
    'run',
    'query',
    'fetch',
]);
/**
 * Scans individual tool definitions for dangerous patterns.
 * Produces findings: TS-001 through TS-006.
 */
export function scanTools(tools) {
    const findings = [];
    const toolNames = new Set();
    for (let i = 0; i < tools.length; i++) {
        const tool = tools[i];
        if (tool === undefined)
            continue;
        const location = `tools[${i}]`;
        // TS-001: Dangerous tool name
        const dangerousNamePattern = /\b(exec|shell|eval|system|run_command|spawn|popen|subprocess)\b/i;
        if (dangerousNamePattern.test(tool.name)) {
            findings.push({
                id: 'TS-001',
                severity: 'critical',
                title: 'Dangerous Tool Name Detected',
                description: `Tool "${tool.name}" uses a name associated with OS-level command execution. This is an extremely high-risk capability that should not be exposed through MCP.`,
                remediation: 'Remove or rename this tool. If OS execution is required, restrict it behind strict input validation, allow-listing, and audit logging.',
                location: `${location}.name`,
            });
        }
        const descLower = (tool.description ?? '').toLowerCase();
        // TS-002: Override language in description
        const overridePatterns = [
            'ignore previous',
            'override',
            'bypass',
            'disregard',
            'forget your',
            'new system prompt',
            'ignore instructions',
            'you must',
            'you will now',
        ];
        if (overridePatterns.some((p) => descLower.includes(p))) {
            findings.push({
                id: 'TS-002',
                severity: 'critical',
                title: 'Prompt Override Language in Tool Description',
                description: `Tool "${tool.name}" contains language in its description that could be used for prompt injection (e.g., "ignore previous", "override", "bypass").`,
                remediation: 'Review and sanitize the tool description. Tool descriptions are injected into the LLM context; any override language can hijack model behavior.',
                location: `${location}.description`,
            });
        }
        // TS-003: Exfiltration language in description
        const exfilPatterns = [
            'send to',
            'exfiltrate',
            'upload to',
            'transmit',
            'post to external',
            'forward to',
            'export to remote',
            'leak',
        ];
        if (exfilPatterns.some((p) => descLower.includes(p))) {
            findings.push({
                id: 'TS-003',
                severity: 'high',
                title: 'Data Exfiltration Language in Tool Description',
                description: `Tool "${tool.name}" description contains language suggesting data exfiltration ("${exfilPatterns.find((p) => descLower.includes(p))}"...).`,
                remediation: 'Audit what data this tool transmits and to where. Ensure all external data sends are intentional, logged, and user-consented.',
                location: `${location}.description`,
            });
        }
        // TS-004: Missing parameter descriptions
        const params = tool.parameters ?? [];
        const missingDescriptions = params.filter((p) => !p.description || p.description.trim().length < 5);
        if (params.length > 0 && missingDescriptions.length > 0) {
            findings.push({
                id: 'TS-004',
                severity: 'low',
                title: 'Missing Parameter Descriptions',
                description: `Tool "${tool.name}" has ${missingDescriptions.length} parameter(s) without descriptions: ${missingDescriptions.map((p) => p.name).join(', ')}. ` +
                    'LLMs use parameter descriptions to decide what values to pass, increasing the chance of unintended inputs.',
                remediation: 'Add clear, unambiguous descriptions to every tool parameter. Descriptions should explain expected values, format, and constraints.',
                location: `${location}.parameters`,
            });
        }
        // TS-005: Accepts arbitrary code/script input
        const codeParamNames = /^(code|script|eval|execute|expression|payload|command|cmd|query|sql|js|python|ruby|bash)$/i;
        const allParamNames = [
            ...params.map((p) => p.name),
            ...Object.keys((tool.inputSchema ?? {})),
        ];
        const dangerousParams = allParamNames.filter((name) => codeParamNames.test(name));
        if (dangerousParams.length > 0) {
            findings.push({
                id: 'TS-005',
                severity: 'critical',
                title: 'Tool Accepts Arbitrary Code or Script Input',
                description: `Tool "${tool.name}" accepts parameter(s) that suggest arbitrary code execution: ${dangerousParams.join(', ')}. ` +
                    'This is a critical attack surface for remote code execution through prompt injection.',
                remediation: 'Replace free-form code parameters with structured, validated inputs. If code execution is required, use a sandbox with strict capability restrictions.',
                location: `${location}.parameters[${dangerousParams.join(', ')}]`,
            });
        }
        // TS-006: Tool name shadows common safe tools
        if (SAFE_TOOL_NAMES.has(tool.name.toLowerCase())) {
            // Check if it was already defined — shadowing
            if (toolNames.has(tool.name.toLowerCase())) {
                findings.push({
                    id: 'TS-006',
                    severity: 'high',
                    title: 'Tool Name Shadows Another Tool',
                    description: `Tool "${tool.name}" duplicates a name already defined in this server. Duplicate names can cause the LLM to invoke the wrong tool.`,
                    remediation: 'Ensure all tool names within a server are unique. Use namespaced names (e.g., "files.read", "db.query") to avoid ambiguity.',
                    location: `${location}.name`,
                });
            }
        }
        toolNames.add(tool.name.toLowerCase());
    }
    return findings;
}
//# sourceMappingURL=tool-scanner.js.map