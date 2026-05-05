import type { OutputFormat, ScanReport } from '../types.js';
/**
 * Renders a ScanReport to the chosen output format string.
 */
export declare function renderReport(report: ScanReport, outputFormat: OutputFormat, useColor?: boolean): string;
/**
 * Loads a saved scan report from a JSON file and renders it.
 */
export declare function renderReportFile(filePath: string, outputFormat: OutputFormat, useColor?: boolean): string;
//# sourceMappingURL=index.d.ts.map