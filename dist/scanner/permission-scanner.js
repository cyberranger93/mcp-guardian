/**
 * Scans MCP server permission configuration for over-broad grants.
 * Produces findings: PS-001 through PS-004.
 */
export function scanPermissions(permissions) {
    const findings = [];
    // PS-003: Missing permission scope definitions (check first — others depend on presence)
    if (!permissions || Object.keys(permissions).length === 0) {
        findings.push({
            id: 'PS-003',
            severity: 'high',
            title: 'Missing Permission Scope Definitions',
            description: 'The server manifest does not declare any permission scopes. Without explicit permissions, the actual access granted is opaque to auditors and tooling.',
            remediation: 'Add a "permissions" block that explicitly declares filesystem, network, and scope permissions. Apply least-privilege principles.',
            location: 'permissions',
        });
        // Can't scan further if no permissions object at all
        return findings;
    }
    // PS-001: Filesystem write permissions too broad
    const writePaths = permissions.filesystem?.write ?? [];
    const broadWritePaths = writePaths.filter((p) => p === '/' || p === '*' || p === '**' || p === '.' || p === './' || p === '/home');
    if (broadWritePaths.length > 0) {
        findings.push({
            id: 'PS-001',
            severity: 'critical',
            title: 'Filesystem Write Permissions Too Broad',
            description: `The server grants write access to overly broad paths: ${broadWritePaths.join(', ')}. ` +
                'This could allow the server to modify arbitrary files on the host system, including system files and credential stores.',
            remediation: 'Restrict filesystem write permissions to the specific directories the server needs. Use absolute paths to a dedicated working directory.',
            location: 'permissions.filesystem.write',
        });
    }
    // PS-002: Network permissions unrestricted
    const networkPerms = permissions.network;
    if (networkPerms?.allowAllHosts === true) {
        findings.push({
            id: 'PS-002',
            severity: 'critical',
            title: 'Network Permissions Unrestricted',
            description: 'The server is configured with "allowAllHosts: true", granting unrestricted outbound network access. ' +
                'This enables data exfiltration to any external host.',
            remediation: 'Replace "allowAllHosts: true" with an explicit "allowedHosts" list containing only the required external hosts. ' +
                'Apply network-level egress filtering where possible.',
            location: 'permissions.network.allowAllHosts',
        });
    }
    else if (networkPerms !== undefined && (!networkPerms.allowedHosts || networkPerms.allowedHosts.length === 0)) {
        findings.push({
            id: 'PS-002',
            severity: 'medium',
            title: 'Network Allowed Hosts Not Specified',
            description: 'The server declares network permissions but does not specify an "allowedHosts" allow-list. ' +
                'Without an explicit allow-list, network egress policy is undefined.',
            remediation: 'Define an "allowedHosts" array listing every external host this server legitimately needs to contact.',
            location: 'permissions.network',
        });
    }
    // PS-004: Permissions not least-privilege
    const scopes = permissions.scopes ?? [];
    const broadScopes = scopes.filter((s) => s === '*' ||
        s === 'admin' ||
        s === 'superuser' ||
        s.endsWith(':write') ||
        s.endsWith(':admin') ||
        s.endsWith('/*') ||
        s.endsWith(':*'));
    if (broadScopes.length > 0) {
        findings.push({
            id: 'PS-004',
            severity: 'high',
            title: 'Permissions Not Least-Privilege',
            description: `The following scopes grant elevated or broad access: ${broadScopes.join(', ')}. ` +
                'Over-privileged scopes violate the principle of least privilege and increase blast radius if the server is compromised.',
            remediation: 'Audit each scope and remove any that are not strictly required. Prefer read-only scopes over write, and specific resource scopes over wildcards.',
            location: 'permissions.scopes',
        });
    }
    return findings;
}
//# sourceMappingURL=permission-scanner.js.map