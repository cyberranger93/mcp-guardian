#!/usr/bin/env node
import { Command } from 'commander';
import { watch } from 'chokidar';
import { writeFileSync } from 'fs';
import { scanFile, shouldFail } from '../scanner/index.js';
import { loadPolicy } from '../firewall/policy.js';
import { renderReport, renderReportFile } from '../reporter/index.js';
const program = new Command();
program
    .name('mcp-guardian')
    .description('MCP server scanner, runtime firewall, and CI guardrail for AI agents')
    .version('0.1.0');
// ─── scan ────────────────────────────────────────────────────────────────────
program
    .command('scan <server>')
    .description('Scan an MCP server manifest JSON for vulnerabilities')
    .option('-o, --output <format>', 'Output format: json | table | sarif', 'table')
    .option('-p, --policy <policy>', 'Policy to apply: strict | standard | audit | path/to/policy.json', 'standard')
    .option('--fail-on <severity>', 'Exit with code 1 if any finding meets or exceeds this severity: critical | high | medium', 'high')
    .option('--save <path>', 'Save the raw scan JSON to a file (useful for later rendering or SARIF upload)')
    .option('--no-color', 'Disable color output')
    .action(async (serverPath, opts) => {
    const outputFormat = validateOutputFormat(opts.output);
    const failOn = validateFailThreshold(opts.failOn);
    // Validate policy (loads it to confirm it's valid, but the scanner doesn't use it yet — it's for firewall)
    try {
        loadPolicy(opts.policy);
    }
    catch (err) {
        console.error(`Error loading policy: ${err instanceof Error ? err.message : String(err)}`);
        process.exit(2);
    }
    let report;
    try {
        report = scanFile(serverPath);
    }
    catch (err) {
        console.error(`Scan error: ${err instanceof Error ? err.message : String(err)}`);
        process.exit(2);
    }
    // Save raw JSON if requested
    if (opts.save) {
        try {
            writeFileSync(opts.save, JSON.stringify(report, null, 2), 'utf8');
            console.error(`Scan result saved to: ${opts.save}`);
        }
        catch (err) {
            console.error(`Warning: could not save to "${opts.save}": ${err instanceof Error ? err.message : String(err)}`);
        }
    }
    // Render and print
    const rendered = renderReport(report, outputFormat, opts.color);
    process.stdout.write(rendered + '\n');
    // Exit code
    if (shouldFail(report, failOn)) {
        process.exit(1);
    }
    process.exit(0);
});
// ─── watch ───────────────────────────────────────────────────────────────────
program
    .command('watch <server>')
    .description('Watch an MCP server manifest JSON and re-scan on every change')
    .option('-o, --output <format>', 'Output format: json | table | sarif', 'table')
    .option('-p, --policy <policy>', 'Policy to apply', 'standard')
    .option('--no-color', 'Disable color output')
    .action((serverPath, opts) => {
    const outputFormat = validateOutputFormat(opts.output);
    console.log(`Watching ${serverPath} for changes. Press Ctrl+C to stop.\n`);
    // Run initial scan
    runAndPrint(serverPath, outputFormat, opts.color);
    const watcher = watch(serverPath, { persistent: true, ignoreInitial: true });
    watcher.on('change', () => {
        console.log(`\n[${new Date().toISOString()}] Change detected — rescanning...\n`);
        runAndPrint(serverPath, outputFormat, opts.color);
    });
    watcher.on('error', (err) => {
        console.error(`Watcher error: ${err instanceof Error ? err.message : String(err)}`);
    });
});
// ─── report ──────────────────────────────────────────────────────────────────
program
    .command('report <scan-output>')
    .description('Render a previously saved scan JSON result')
    .option('-o, --output <format>', 'Output format: json | table | sarif', 'table')
    .option('--no-color', 'Disable color output')
    .action((reportPath, opts) => {
    const outputFormat = validateOutputFormat(opts.output);
    let rendered;
    try {
        rendered = renderReportFile(reportPath, outputFormat, opts.color);
    }
    catch (err) {
        console.error(`Error rendering report: ${err instanceof Error ? err.message : String(err)}`);
        process.exit(2);
    }
    process.stdout.write(rendered + '\n');
});
// ─── Helpers ─────────────────────────────────────────────────────────────────
function runAndPrint(serverPath, outputFormat, color) {
    try {
        const report = scanFile(serverPath);
        const rendered = renderReport(report, outputFormat, color);
        process.stdout.write(rendered + '\n');
    }
    catch (err) {
        console.error(`Scan error: ${err instanceof Error ? err.message : String(err)}`);
    }
}
function validateOutputFormat(val) {
    if (val === 'json' || val === 'table' || val === 'sarif')
        return val;
    console.error(`Invalid output format "${val}". Must be one of: json, table, sarif`);
    process.exit(2);
}
function validateFailThreshold(val) {
    if (val === 'critical' || val === 'high' || val === 'medium')
        return val;
    console.error(`Invalid --fail-on value "${val}". Must be one of: critical, high, medium`);
    process.exit(2);
}
program.parse(process.argv);
//# sourceMappingURL=index.js.map