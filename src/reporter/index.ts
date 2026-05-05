import { readFileSync } from 'fs';
import type { OutputFormat, ScanReport } from '../types.js';
import { format } from './formatters.js';

/**
 * Renders a ScanReport to the chosen output format string.
 */
export function renderReport(report: ScanReport, outputFormat: OutputFormat, useColor: boolean = true): string {
  return format(report, outputFormat, useColor);
}

/**
 * Loads a saved scan report from a JSON file and renders it.
 */
export function renderReportFile(
  filePath: string,
  outputFormat: OutputFormat,
  useColor: boolean = true,
): string {
  let raw: string;
  try {
    raw = readFileSync(filePath, 'utf8');
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Cannot read report file "${filePath}": ${msg}`);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(`File "${filePath}" is not valid JSON.`);
  }

  assertScanReport(parsed);
  return format(parsed, outputFormat, useColor);
}

function assertScanReport(value: unknown): asserts value is ScanReport {
  if (typeof value !== 'object' || value === null) {
    throw new Error('Report file must contain a JSON object');
  }
  const obj = value as Record<string, unknown>;
  if (typeof obj['server'] !== 'string') throw new Error('Report missing "server" field');
  if (typeof obj['timestamp'] !== 'string') throw new Error('Report missing "timestamp" field');
  if (!Array.isArray(obj['findings'])) throw new Error('Report missing "findings" array');
  if (typeof obj['passed'] !== 'boolean') throw new Error('Report missing "passed" field');
  if (typeof obj['score'] !== 'number') throw new Error('Report missing "score" field');
}
