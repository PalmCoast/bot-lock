import type { Policy, ScopeDecision, ScopeRequest } from "./types.js";
export declare function defaultPolicy(): Policy;
export declare function checkScope(policy: Policy, request: ScopeRequest): ScopeDecision;
export declare function engageKillSwitch(policy: Policy, reason: string): Policy;
export declare function releaseKillSwitch(policy: Policy): Policy;
