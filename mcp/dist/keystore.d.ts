/**
 * Where the vault master key lives. It is never written into state.json.
 *
 * Resolution order:
 *   1. BOTLOCK_MASTER_KEY environment variable
 *   2. OS keychain (macOS Keychain via `security`, Linux Secret Service via `secret-tool`)
 *   3. A separate key file, mode 0600 (default $BOTLOCK_HOME/master.key, override BOTLOCK_KEY_FILE)
 */
export type KeySource = "env" | "keychain" | "file" | "none";
export type ResolvedKey = {
    masterKey?: string;
    source: KeySource;
    location?: string;
    warnings: string[];
};
export interface KeychainBackend {
    readonly name: string;
    available(): boolean;
    get(account: string): string | undefined;
    set(account: string, secret: string): void;
}
export declare const macKeychain: KeychainBackend;
export declare const secretService: KeychainBackend;
/** Tests (or embedders) can inject a keychain backend; pass null to force "no keychain". */
export declare function setKeychainBackend(backend: KeychainBackend | null | undefined): void;
export declare function keyFilePath(home: string): string;
export declare const KEY_FILE_WARNING: string;
export type ResolveOptions = {
    /** A key found in a legacy state.json that must be preserved. */
    legacyKey?: string;
    /** Existing sealed secrets: when true, never mint a fresh key silently. */
    hasSecrets: boolean;
};
/**
 * Find the master key, creating one only when the vault is empty.
 * A legacy key (from state.json) is migrated into the keychain or key file.
 */
export declare function resolveMasterKey(home: string, opts: ResolveOptions): ResolvedKey;
