import type { MCPPermissions, ScanFinding } from '../types.js';
/**
 * Scans MCP server permission configuration for over-broad grants.
 * Produces findings: PS-001 through PS-004.
 */
export declare function scanPermissions(permissions: MCPPermissions | undefined): ScanFinding[];
//# sourceMappingURL=permission-scanner.d.ts.map