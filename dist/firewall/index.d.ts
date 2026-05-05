import type { FirewallDecision, FirewallRule, Policy, ToolCall } from '../types.js';
export declare class ToolCallFirewall {
    private readonly policy;
    private readonly rules;
    constructor(policy: Policy);
    inspect(call: ToolCall): FirewallDecision;
    addRule(rule: FirewallRule): void;
    removeRule(id: string): void;
    listRules(): FirewallRule[];
}
//# sourceMappingURL=index.d.ts.map