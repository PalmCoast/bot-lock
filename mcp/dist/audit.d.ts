import type { AuditEntry } from "./types.js";
export declare const GENESIS_HASH: string;
export declare function payloadDigest(payload: unknown): string;
export declare function computeHash(input: {
    seq: number;
    ts: string;
    actor: string;
    action: string;
    payloadHash: string;
    prevHash: string;
}): string;
export declare function appendAudit(args: {
    chain: AuditEntry[];
    actor: string;
    action: string;
    payload: unknown;
    privateKeyPem: string;
}): AuditEntry;
export declare function verifyChain(chain: AuditEntry[], publicKeyPem: string): {
    valid: boolean;
    brokenAt?: number;
    reason?: string;
};
