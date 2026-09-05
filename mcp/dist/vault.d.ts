import type { VaultMeta } from "./types.js";
export type SealedSecret = VaultMeta & {
    ciphertext: string;
    iv: string;
    tag: string;
    salt: string;
};
export declare function deriveKey(masterKey: string, salt: Buffer): Buffer;
export declare function sealSecret(masterKey: string, name: string, plaintext: string, identityId: string): SealedSecret;
export declare function openSecret(masterKey: string, sealed: SealedSecret): string;
export declare function secretFingerprint(plaintext: string): string;
export declare function publicMeta(sealed: SealedSecret): VaultMeta;
export declare function generateMasterKey(): string;
