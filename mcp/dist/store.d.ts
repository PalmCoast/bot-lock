import type { AuditEntry, Policy, StoredIdentity } from "./types.js";
import type { SealedSecret } from "./vault.js";
export type BotLockState = {
    identity?: StoredIdentity;
    masterKey?: string;
    secrets: Record<string, SealedSecret>;
    audit: AuditEntry[];
    policy: Policy;
};
export declare function defaultHome(): string;
export declare function statePath(home?: string): string;
export declare function loadState(home?: string): BotLockState;
export declare function saveState(state: BotLockState, home?: string): void;
export declare function withState<T>(fn: (state: BotLockState) => T, home?: string): T;
