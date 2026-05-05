import { readFileSync } from 'fs';
import { scanManifest } from './manifest-scanner.js';
import { scanTools } from './tool-scanner.js';
import { scanPermissions } from './permission-scanner.js';
// Severity → point deduction for score calculation
const SEVERITY_PENALTIES = {
    critical: 25,
    high: 15,
    medium: 8,
    low: 3,
    info: 0,
};
/**
 * Loads and validates an MCP server manifest from a file path.
 */
export function loadManifest(filePath) {
    let raw;
    try {
        raw = readFileSync(filePath, 'utf8');
    }
    catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        throw new Error(`Cannot read manifest file "${filePath}": ${msg}`);
    }
    let parsed;
    try {
        parsed = JSON.parse(raw);
    }
    catch {
        throw new Error(`File "${filePath}" is not valid JSON.`);
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
        throw new Error(`File "${filePath}" must contain a JSON object at the root.`);
    }
    return parsed;
}
/**
 * Runs all scanners against an MCP server manifest and returns a ScanReport.
 */
export function scanServer(manifest, serverLabel) {
    const findings = [
        ...scanManifest(manifest),
        ...scanTools(manifest.tools ?? []),
        ...scanPermissions(manifest.permissions),
    ];
    const score = calculateScore(findings);
    const passed = !findings.some((f) => f.severity === 'critical' || f.severity === 'high');
    return {
        server: serverLabel,
        timestamp: new Date().toISOString(),
        findings,
        passed,
        score,
    };
}
/**
 * Scans a manifest file by path and returns a ScanReport.
 */
export function scanFile(filePath) {
    const manifest = loadManifest(filePath);
    return scanServer(manifest, filePath);
}
/**
 * Determines whether a ScanReport should fail CI based on the threshold.
 * Returns exit code: 0 = pass, 1 = findings above threshold, 2 = scan error.
 */
export function shouldFail(report, threshold) {
    const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
    const thresholdIndex = severityOrder.indexOf(threshold);
    return report.findings.some((f) => severityOrder.indexOf(f.severity) <= thresholdIndex);
}
function calculateScore(findings) {
    const totalPenalty = findings.reduce((sum, f) => sum + (SEVERITY_PENALTIES[f.severity] ?? 0), 0);
    return Math.max(0, 100 - totalPenalty);
}
//# sourceMappingURL=index.js.map