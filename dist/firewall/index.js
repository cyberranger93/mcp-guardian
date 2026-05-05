import { builtinRules } from './rules.js';
// Severities that are blocked in deny mode (critical + high always block in strict)
const BLOCKING_SEVERITIES = ['critical', 'high'];
export class ToolCallFirewall {
    policy;
    rules;
    constructor(policy) {
        this.policy = policy;
        this.rules = new Map(builtinRules.map((r) => [r.id, r]));
    }
    inspect(call) {
        const { defaultMode, rules: overrides = [] } = this.policy;
        for (const [id, rule] of this.rules) {
            if (!rule.match(call))
                continue;
            // Check for policy override on this rule
            const override = overrides.find((o) => o.ruleId === id);
            if (override?.action === 'skip')
                continue;
            // Audit mode: log but allow
            if (defaultMode === 'audit') {
                return {
                    allowed: true,
                    reason: `[audit] Rule ${id} matched: ${rule.name}`,
                    matchedRule: id,
                };
            }
            // Allow mode: nothing is blocked
            if (defaultMode === 'allow') {
                return {
                    allowed: true,
                    reason: `[allow] Rule ${id} matched but policy is allow-mode`,
                    matchedRule: id,
                };
            }
            // Deny mode: check severity
            const effectiveSeverity = override?.action === 'downgrade'
                ? downgrade(rule.severity)
                : override?.action === 'elevate'
                    ? elevate(rule.severity)
                    : rule.severity;
            if (BLOCKING_SEVERITIES.includes(effectiveSeverity)) {
                return {
                    allowed: false,
                    reason: `Blocked by rule ${id} (${effectiveSeverity}): ${rule.name}`,
                    matchedRule: id,
                };
            }
            // Medium/low/info in deny mode → audit (log but allow)
            return {
                allowed: true,
                reason: `[audit] Rule ${id} matched at ${effectiveSeverity}: ${rule.name}`,
                matchedRule: id,
            };
        }
        // No rule matched
        return { allowed: true };
    }
    addRule(rule) {
        this.rules.set(rule.id, rule);
    }
    removeRule(id) {
        this.rules.delete(id);
    }
    listRules() {
        return Array.from(this.rules.values());
    }
}
// ─── Severity helpers ────────────────────────────────────────────────────────
function downgrade(s) {
    const order = ['critical', 'high', 'medium', 'low', 'info'];
    const idx = order.indexOf(s);
    return order[Math.min(idx + 1, order.length - 1)] ?? 'info';
}
function elevate(s) {
    const order = ['critical', 'high', 'medium', 'low', 'info'];
    const idx = order.indexOf(s);
    return order[Math.max(idx - 1, 0)] ?? 'critical';
}
//# sourceMappingURL=index.js.map