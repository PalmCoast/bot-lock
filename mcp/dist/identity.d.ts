import type { StoredIdentity } from "./types.js";
export declare function createIdentity(label?: string): StoredIdentity;
export declare function publicView(identity: StoredIdentity): {
    id: string;
    label: string;
    publicKeyPem: string;
    createdAt: string;
};
export declare function signMessage(privateKeyPem: string, message: string | Buffer): string;
export declare function verifyMessage(publicKeyPem: string, message: string | Buffer, signatureB64: string): boolean;
export declare function fingerprint(publicKeyPem: string): string;
