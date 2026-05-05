import type { MCPServerManifest, ScanFinding } from '../types.js';
/**
 * Scans the top-level MCP server manifest for structural and configuration issues.
 * Produces findings: MS-001 through MS-005.
 */
export declare function scanManifest(manifest: MCPServerManifest): ScanFinding[];
//# sourceMappingURL=manifest-scanner.d.ts.map