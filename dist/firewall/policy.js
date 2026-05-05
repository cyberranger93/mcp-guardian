import { readFileSync } from 'fs';
export const BUILTIN_POLICIES = {
    strict: {
        name: 'strict',
        description: 'Deny-by-default. All critical and high rules enforced. Zero tolerance.',
        defaultMode: 'deny',
    },
    standard: {
        name: 'standard',
        description: 'Block critical and high severity matches. Audit medium and low.',
        defaultMode: 'deny',
        rules: [
            { ruleId: 'FW-006', action: 'downgrade' }, // Rate limit → audit only in standard
            { ruleId: 'FW-009', action: 'downgrade' }, // HTTP → audit only in standard
            { ruleId: 'FW-014', action: 'downgrade' }, // Oversized args → audit only in standard
        ],
    },
    audit: {
        name: 'audit',
        description: 'Audit-only mode — log all matches but never block.',
        defaultMode: 'audit',
    },
};
export function loadPolicy(nameOrPath) {
    const builtin = BUILTIN_POLICIES[nameOrPath];
    if (builtin !== undefined)
        return builtin;
    // Try to load from file path
    try {
        const raw = readFileSync(nameOrPath, 'utf8');
        const parsed = JSON.parse(raw);
        assertPolicy(parsed);
        return parsed;
    }
    catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        throw new Error(`Failed to load policy from "${nameOrPath}": ${message}`);
    }
}
function assertPolicy(value) {
    if (typeof value !== 'object' || value === null) {
        throw new Error('Policy must be a JSON object');
    }
    const obj = value;
    if (typeof obj['name'] !== 'string')
        throw new Error('Policy missing "name" string field');
    if (typeof obj['description'] !== 'string')
        throw new Error('Policy missing "description" string field');
    if (obj['defaultMode'] !== 'allow' && obj['defaultMode'] !== 'deny' && obj['defaultMode'] !== 'audit') {
        throw new Error('Policy "defaultMode" must be "allow", "deny", or "audit"');
    }
}
//# sourceMappingURL=policy.js.map