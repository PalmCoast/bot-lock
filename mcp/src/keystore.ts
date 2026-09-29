import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { generateMasterKey } from "./vault.js";

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

const SERVICE = "bot-lock-mcp";

function run(cmd: string, args: string[], input?: string): string {
  return execFileSync(cmd, args, {
    input,
    encoding: "utf8",
    stdio: ["pipe", "pipe", "ignore"],
    timeout: 5000,
  }).trim();
}

function hasCommand(cmd: string): boolean {
  try {
    execFileSync("which", [cmd], { stdio: "ignore", timeout: 2000 });
    return true;
  } catch {
    return false;
  }
}

export const macKeychain: KeychainBackend = {
  name: "macOS Keychain",
  available: () => process.platform === "darwin" && hasCommand("security"),
  get(account) {
    try {
      return run("security", ["find-generic-password", "-s", SERVICE, "-a", account, "-w"]) || undefined;
    } catch {
      return undefined;
    }
  },
  set(account, secret) {
    run("security", ["add-generic-password", "-U", "-s", SERVICE, "-a", account, "-w", secret]);
  },
};

export const secretService: KeychainBackend = {
  name: "Secret Service (secret-tool)",
  available: () =>
    process.platform === "linux" && Boolean(process.env.DBUS_SESSION_BUS_ADDRESS) && hasCommand("secret-tool"),
  get(account) {
    try {
      return run("secret-tool", ["lookup", "service", SERVICE, "account", account]) || undefined;
    } catch {
      return undefined;
    }
  },
  set(account, secret) {
    run("secret-tool", ["store", "--label=Bot Lock MCP master key", "service", SERVICE, "account", account], secret);
  },
};

let backendOverride: KeychainBackend | null | undefined;
const keychainCache = new Map<string, string>();

/** Tests (or embedders) can inject a keychain backend; pass null to force "no keychain". */
export function setKeychainBackend(backend: KeychainBackend | null | undefined): void {
  backendOverride = backend;
  keychainCache.clear();
}

function keychainDisabled(): boolean {
  const v = (process.env.BOTLOCK_KEYCHAIN ?? "").toLowerCase();
  return v === "0" || v === "off" || v === "false" || v === "no";
}

function pickKeychain(): KeychainBackend | undefined {
  if (backendOverride !== undefined) return backendOverride ?? undefined;
  if (keychainDisabled()) return undefined;
  for (const b of [macKeychain, secretService]) {
    try {
      if (b.available()) return b;
    } catch {
      /* ignore */
    }
  }
  return undefined;
}

export function keyFilePath(home: string): string {
  return process.env.BOTLOCK_KEY_FILE || join(home, "master.key");
}

export const KEY_FILE_WARNING =
  "Bot Lock: the vault master key is stored in a key file (0600), not an OS keychain. " +
  "Anyone who can read both that file and state.json can decrypt your secrets. " +
  "For stronger protection set BOTLOCK_MASTER_KEY from a secret manager, or put BOTLOCK_KEY_FILE on a different disk, and back the key up: losing it makes stored secrets unrecoverable.";

function readKeyFile(path: string, warnings: string[]): string | undefined {
  if (!existsSync(path)) return undefined;
  if (process.platform !== "win32") {
    const mode = statSync(path).mode & 0o777;
    if (mode & 0o077) {
      chmodSync(path, 0o600);
      warnings.push(`Key file ${path} was readable by other users (mode ${mode.toString(8)}); reset to 600.`);
    }
  }
  const key = readFileSync(path, "utf8").trim();
  if (!key) throw new Error(`Key file ${path} exists but is empty. Restore the key or delete the file if the vault is empty.`);
  return key;
}

function writeKeyFile(path: string, key: string): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  writeFileSync(path, key + "\n", { mode: 0o600, flag: "wx" });
  if (process.platform !== "win32") chmodSync(path, 0o600);
}

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
export function resolveMasterKey(home: string, opts: ResolveOptions): ResolvedKey {
  const warnings: string[] = [];
  const envKey = process.env.BOTLOCK_MASTER_KEY?.trim();

  if (envKey) {
    if (opts.legacyKey && opts.legacyKey !== envKey) {
      throw new Error(
        "BOTLOCK_MASTER_KEY differs from the key stored in the old state.json that sealed your existing secrets. " +
          "Unset BOTLOCK_MASTER_KEY once so Bot Lock can migrate the old key, or set BOTLOCK_MASTER_KEY to the old key.",
      );
    }
    return { masterKey: envKey, source: "env", location: "BOTLOCK_MASTER_KEY", warnings };
  }

  const account = home;
  const kc = pickKeychain();
  if (kc) {
    try {
      const existing = keychainCache.get(account) ?? kc.get(account);
      if (existing && !opts.legacyKey) keychainCache.set(account, existing);
      if (existing && opts.legacyKey && existing !== opts.legacyKey) {
        throw new Error(
          `The ${kc.name} entry for ${home} differs from the key in the old state.json. Refusing to migrate; resolve manually.`,
        );
      }
      if (existing) return { masterKey: existing, source: "keychain", location: kc.name, warnings };
      const key = opts.legacyKey ?? (opts.hasSecrets ? undefined : generateMasterKey());
      if (key) {
        kc.set(account, key);
        if (kc.get(account) === key) keychainCache.set(account, key);
        if (keychainCache.get(account) === key) return { masterKey: key, source: "keychain", location: kc.name, warnings };
        warnings.push(`${kc.name} did not return the stored key; falling back to a key file.`);
      }
    } catch (err) {
      if (err instanceof Error && /Refusing to migrate/.test(err.message)) throw err;
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
    warnings.push(
      "Vault master key not found (no BOTLOCK_MASTER_KEY, keychain entry or key file) but sealed secrets exist. They cannot be opened until the key is restored.",
    );
    return { source: "none", warnings };
  }
  writeKeyFile(path, key);
  warnings.push(KEY_FILE_WARNING);
  return { masterKey: key, source: "file", location: path, warnings };
}
