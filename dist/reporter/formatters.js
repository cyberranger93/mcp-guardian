// ─── Severity → SARIF level mapping ─────────────────────────────────────────
function toSarifLevel(severity) {
    switch (severity) {
        case 'critical':
        case 'high':
            return 'error';
        case 'medium':
            return 'warning';
        case 'low':
            return 'note';
        case 'info':
            return 'none';
    }
}
// ─── Formatters ──────────────────────────────────────────────────────────────
export function formatJson(report) {
    return JSON.stringify(report, null, 2);
}
export function formatSarif(report) {
    const sarifOutput = {
        $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
        version: '2.1.0',
        runs: [
            {
                tool: {
                    driver: {
                        name: 'mcp-guardian',
                        version: '0.1.0',
                        informationUri: 'https://github.com/cyberranger93/mcp-guardian',
                        rules: report.findings.map((f) => ({
                            id: f.id,
                            name: f.title.replace(/\s+/g, ''),
                            shortDescription: { text: f.title },
                            properties: { severity: f.severity },
                        })),
                    },
                },
                results: report.findings.map((f) => ({
                    ruleId: f.id,
                    level: toSarifLevel(f.severity),
                    message: { text: `${f.description}\n\nRemediation: ${f.remediation}` },
                    locations: [
                        {
                            logicalLocations: [
                                {
                                    name: f.location ?? report.server,
                                    kind: 'module',
                                },
                            ],
                        },
                    ],
                    properties: {
                        severity: f.severity,
                        remediation: f.remediation,
                    },
                })),
            },
        ],
    };
    return JSON.stringify(sarifOutput, null, 2);
}
export function formatTable(report, useColor = true) {
    const lines = [];
    // Color helpers — no chalk dependency in formatter (chalk imported by reporter/index)
    const c = {
        reset: useColor ? '\x1b[0m' : '',
        bold: useColor ? '\x1b[1m' : '',
        red: useColor ? '\x1b[31m' : '',
        yellow: useColor ? '\x1b[33m' : '',
        cyan: useColor ? '\x1b[36m' : '',
        green: useColor ? '\x1b[32m' : '',
        gray: useColor ? '\x1b[90m' : '',
        magenta: useColor ? '\x1b[35m' : '',
    };
    function severityColor(severity) {
        switch (severity) {
            case 'critical': return c.red + c.bold;
            case 'high': return c.red;
            case 'medium': return c.yellow;
            case 'low': return c.cyan;
            case 'info': return c.gray;
        }
    }
    const scoreColor = report.score >= 80 ? c.green : report.score >= 50 ? c.yellow : c.red;
    const passedLabel = report.passed
        ? `${c.green}PASSED${c.reset}`
        : `${c.red}FAILED${c.reset}`;
    lines.push('');
    lines.push(`${c.bold}╔══════════════════════════════════════════════════════════════╗${c.reset}`);
    lines.push(`${c.bold}║              MCP GUARDIAN — SCAN REPORT                      ║${c.reset}`);
    lines.push(`${c.bold}╚══════════════════════════════════════════════════════════════╝${c.reset}`);
    lines.push('');
    lines.push(`  Server   : ${c.bold}${report.server}${c.reset}`);
    lines.push(`  Scanned  : ${report.timestamp}`);
    lines.push(`  Score    : ${scoreColor}${c.bold}${report.score}/100${c.reset}`);
    lines.push(`  Status   : ${passedLabel}`);
    lines.push('');
    if (report.findings.length === 0) {
        lines.push(`  ${c.green}No findings. Server configuration looks clean.${c.reset}`);
        lines.push('');
        return lines.join('\n');
    }
    // Count by severity
    const counts = {};
    for (const f of report.findings) {
        counts[f.severity] = (counts[f.severity] ?? 0) + 1;
    }
    lines.push(`  Findings : ${report.findings.length} total`);
    for (const [severity, count] of Object.entries(counts)) {
        lines.push(`    ${severityColor(severity)}${severity.toUpperCase()}${c.reset}: ${count}`);
    }
    lines.push('');
    lines.push(`${'─'.repeat(66)}`);
    for (const finding of report.findings) {
        const sev = finding.severity.toUpperCase().padEnd(8);
        lines.push('');
        lines.push(`  ${severityColor(finding.severity)}[${sev}]${c.reset} ${c.bold}${finding.id}${c.reset}: ${finding.title}`);
        if (finding.location) {
            lines.push(`  ${c.gray}Location   : ${finding.location}${c.reset}`);
        }
        lines.push(`  ${c.gray}Description: ${finding.description}${c.reset}`);
        lines.push(`  ${c.cyan}Remediation: ${finding.remediation}${c.reset}`);
    }
    lines.push('');
    lines.push(`${'─'.repeat(66)}`);
    lines.push('');
    return lines.join('\n');
}
export function format(report, outputFormat, useColor = true) {
    switch (outputFormat) {
        case 'json':
            return formatJson(report);
        case 'sarif':
            return formatSarif(report);
        case 'table':
            return formatTable(report, useColor);
    }
}
//# sourceMappingURL=formatters.js.map