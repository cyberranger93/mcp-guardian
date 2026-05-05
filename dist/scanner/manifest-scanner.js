/**
 * Scans the top-level MCP server manifest for structural and configuration issues.
 * Produces findings: MS-001 through MS-005.
 */
export function scanManifest(manifest) {
    const findings = [];
    // MS-001: Missing server authentication
    if (!manifest.auth || manifest.auth.required === false || manifest.auth.required === undefined) {
        findings.push({
            id: 'MS-001',
            severity: 'high',
            title: 'Missing Server Authentication',
            description: 'The MCP server manifest does not declare required authentication. Any client can connect and invoke tools without credentials.',
            remediation: 'Add an "auth" block with "required: true" and specify an auth type (e.g., bearer, apiKey). Enforce token validation on every tool call.',
            location: 'auth',
        });
    }
    // MS-002: Wildcard tool permissions
    const scopes = manifest.permissions?.scopes ?? [];
    const hasWildcard = scopes.some((s) => s === '*' || s.endsWith(':*') || s.endsWith('/*'));
    if (hasWildcard) {
        findings.push({
            id: 'MS-002',
            severity: 'critical',
            title: 'Wildcard Tool Permissions',
            description: `The server declares wildcard permission scopes (${scopes.filter((s) => s === '*' || s.endsWith(':*') || s.endsWith('/*')).join(', ')}). ` +
                'This grants unrestricted access across all tool capabilities.',
            remediation: 'Replace wildcard scopes with explicit, least-privilege permission scopes for each required operation.',
            location: 'permissions.scopes',
        });
    }
    // MS-003: Tool count > 50 (excessive surface area)
    const toolCount = manifest.tools?.length ?? 0;
    if (toolCount > 50) {
        findings.push({
            id: 'MS-003',
            severity: 'medium',
            title: 'Excessive Tool Surface Area',
            description: `The server exposes ${toolCount} tools. Large tool counts increase the attack surface and make it harder to audit each tool's behavior.`,
            remediation: 'Split functionality across multiple purpose-specific MCP servers. Each server should expose only the tools needed for its domain.',
            location: 'tools',
        });
    }
    // MS-004: Missing server description
    if (!manifest.description || manifest.description.trim().length < 10) {
        findings.push({
            id: 'MS-004',
            severity: 'low',
            title: 'Missing Server Description',
            description: 'The server manifest lacks a meaningful description. LLMs use server descriptions to understand tool context; missing descriptions reduce transparency and auditability.',
            remediation: 'Add a clear "description" field that explains what the server does, what data it accesses, and its trust level.',
            location: 'description',
        });
    }
    // MS-005: Version not pinned
    if (!manifest.version || manifest.version.trim() === '' || manifest.version === 'latest') {
        findings.push({
            id: 'MS-005',
            severity: 'medium',
            title: 'Server Version Not Pinned',
            description: 'The server manifest does not declare a specific version or uses "latest". Unpinned versions can introduce breaking changes or security regressions silently.',
            remediation: 'Pin the server to a specific semantic version (e.g., "1.2.3"). Use automated dependency scanning to track version updates.',
            location: 'version',
        });
    }
    return findings;
}
//# sourceMappingURL=manifest-scanner.js.map