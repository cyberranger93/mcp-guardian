import type { ScanReport, OutputFormat } from '../types.js';
export declare function formatJson(report: ScanReport): string;
export declare function formatSarif(report: ScanReport): string;
export declare function formatTable(report: ScanReport, useColor?: boolean): string;
export declare function format(report: ScanReport, outputFormat: OutputFormat, useColor?: boolean): string;
//# sourceMappingURL=formatters.d.ts.map