import type { MCPServerManifest, ScanReport } from '../types.js';
/**
 * Loads and validates an MCP server manifest from a file path.
 */
export declare function loadManifest(filePath: string): MCPServerManifest;
/**
 * Runs all scanners against an MCP server manifest and returns a ScanReport.
 */
export declare function scanServer(manifest: MCPServerManifest, serverLabel: string): ScanReport;
/**
 * Scans a manifest file by path and returns a ScanReport.
 */
export declare function scanFile(filePath: string): ScanReport;
/**
 * Determines whether a ScanReport should fail CI based on the threshold.
 * Returns exit code: 0 = pass, 1 = findings above threshold, 2 = scan error.
 */
export declare function shouldFail(report: ScanReport, threshold: 'critical' | 'high' | 'medium'): boolean;
//# sourceMappingURL=index.d.ts.map