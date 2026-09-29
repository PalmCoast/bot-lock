import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { generateMasterKey } from "./vault.js";
const SERVICE = "bot-lock-mcp";
function run(cmd, args, input) {
    return execFileSync(cmd, args, {
        input,
        encoding: "utf8",
        stdio: ["pipe", "pipe", "ignore"],
        timeout: 5000,
    }).trim();
}
function hasCommand(cmd) {
    try {
        execFileSync("which", [cmd], { stdio: "ignore", timeout: 2000 });
        return true;
    }
    catch {
        return false;
    }
}
export const macKeychain = {
    name: "macOS Keychain",
    available: () => process.platform === "darwin" && hasCommand("security"),
    get(account) {
        try {
            return run("security", ["find-generic-password", "-s", SERVICE, "-a", account, "-w"]) || undefined;
        }
        catch {
            return undefined;
        }
    },
    set(account, secret) {
        run("security", ["add-generic-password", "-U", "-s", SERVICE, "-a", account, "-w", secret]);
    },
};
export const secretService = {
    name: "Secret Service (secret-tool)",
    available: () => process.platform === "linux" && Boolean(process.env.DBUS_SESSION_BUS_ADDRESS) && hasCommand("secret-tool"),
    get(account) {
        try {
            return run("secret-tool", ["lookup", "service", SERVICE, "account", account]) || undefined;
        }
        catch {
            return undefined;
        }
    },
    set(account, secret) {
        run("secret-tool", ["store", "--label=Bot Lock MCP master key", "service", SERVICE, "account", account], secret);
    },
};
let backendOverride;
const keychainCache = new Map();
/** Tests (or embedders) can inject a keychain backend; pass null to force "no keychain". */
export function setKeychainBackend(backend) {
    backendOverride = backend;
    keychainCache.clear();
}
function keychainDisabled() {
    const v = (process.env.BOTLOCK_KEYCHAIN ?? "").toLowerCase();
    return v === "0" || v === "off" || v === "false" || v === "no";
}
function pickKeychain() {
    if (backendOverride !== undefined)
        return backendOverride ?? undefined;
    if (keychainDisabled())
        return undefined;
    for (const b of [macKeychain, secretService]) {
        try {
            if (b.available())
                return b;
        }
        catch {
            /* ignore */
        }
    }
    return undefined;
}
export function keyFilePath(home) {
    return process.env.BOTLOCK_KEY_FILE || join(home, "master.key");
}
export const KEY_FILE_WARNING = "Bot Lock: the vault master key is stored in a key file (0600), not an OS keychain. " +
    "Anyone who can read both that file and state.json can decrypt your secrets. " +
    "For stronger protection set BOTLOCK_MASTER_KEY from a secret manager, or put BOTLOCK_KEY_FILE on a different disk, and back the key up: losing it makes stored secrets unrecoverable.";
function readKeyFile(path, warnings) {
    if (!existsSync(path))
        return undefined;
    if (process.platform !== "win32") {
        const mode = statSync(path).mode & 0o777;
        if (mode & 0o077) {
            chmodSync(path, 0o600);
            warnings.push(`Key file ${path} was readable by other users (mode ${mode.toString(8)}); reset to 600.`);
        }
    }
    const key = readFileSync(path, "utf8").trim();
    if (!key)
        throw new Error(`Key file ${path} exists but is empty. Restore the key or delete the file if the vault is empty.`);
    return key;
}
function writeKeyFile(path, key) {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    writeFileSync(path, key + "\n", { mode: 0o600, flag: "wx" });
    if (process.platform !== "win32")
        chmodSync(path, 0o600);
}
/**
 * Find the master key, creating one only when the vault is empty.
 * A legacy key (from state.json) is migrated into the keychain or key file.
 */
export function resolveMasterKey(home, opts) {
    const warnings = [];
    const envKey = process.env.BOTLOCK_MASTER_KEY?.trim();
    if (envKey) {
        if (opts.legacyKey && opts.legacyKey !== envKey) {
            throw new Error("BOTLOCK_MASTER_KEY differs from the key stored in the old state.json that sealed your existing secrets. " +
                "Unset BOTLOCK_MASTER_KEY once so Bot Lock can migrate the old key, or set BOTLOCK_MASTER_KEY to the old key.");
        }
        return { masterKey: envKey, source: "env", location: "BOTLOCK_MASTER_KEY", warnings };
    }
    const account = home;
    const kc = pickKeychain();
    if (kc) {
        try {
            const existing = keychainCache.get(account) ?? kc.get(account);
            if (existing && !opts.legacyKey)
                keychainCache.set(account, existing);
            if (existing && opts.legacyKey && existing !== opts.legacyKey) {
                throw new Error(`The ${kc.name} entry for ${home} differs from the key in the old state.json. Refusing to migrate; resolve manually.`);
            }
            if (existing)
                return { masterKey: existing, source: "keychain", location: kc.name, warnings };
            const key = opts.legacyKey ?? (opts.hasSecrets ? undefined : generateMasterKey());
            if (key) {
                kc.set(account, key);
                if (kc.get(account) === key)
                    keychainCache.set(account, key);
                if (keychainCache.get(account) === key)
                    return { masterKey: key, source: "keychain", location: kc.name, warnings };
                warnings.push(`${kc.name} did not return the stored key; falling back to a key file.`);
            }
        }
        catch (err) {
            if (err instanceof Error && /Refusing to migrate/.test(err.message))
                throw err;
            warnings.push(`${kc.name} unavailable (${err instanceof Error ? err.message : String(err)}); falling back to a key file.`);
        }
    }
    const path = keyFilePath(home);
    const fromFile = readKeyFile(path, warnings);
    if (fromFile) {
        if (opts.legacyKey && fromFile !== opts.legacyKey) {
            throw new Error(`Key file ${path} differs from the key in the old state.json. Refusing to migrate; resolve manually.`);
        }
        warnings.push(KEY_FILE_WARNING);
        return { masterKey: fromFile, source: "file", location: path, warnings };
    }
    const key = opts.legacyKey ?? (opts.hasSecrets ? undefined : generateMasterKey());
    if (!key) {
        warnings.push("Vault master key not found (no BOTLOCK_MASTER_KEY, keychain entry or key file) but sealed secrets exist. They cannot be opened until the key is restored.");
        return { source: "none", warnings };
    }
    writeKeyFile(path, key);
    warnings.push(KEY_FILE_WARNING);
    return { masterKey: key, source: "file", location: path, warnings };
}
