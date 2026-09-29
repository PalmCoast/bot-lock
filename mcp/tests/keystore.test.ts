import { chmodSync, existsSync, unlinkSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { evaluateStatus } from "../src/status.js";
import { keyFilePath, resolveMasterKey, setKeychainBackend, type KeychainBackend } from "../src/keystore.js";
import { loadState, saveState, statePath } from "../src/store.js";
import { generateMasterKey, openSecret, sealSecret } from "../src/vault.js";
import { createIdentity } from "../src/identity.js";

function home() {
  return mkdtempSync(join(tmpdir(), "botlock-ks-"));
}

function fakeKeychain(): KeychainBackend & { entries: Map<string, string> } {
  const entries = new Map<string, string>();
  return {
    name: "fake keychain",
    entries,
    available: () => true,
    get: (a) => entries.get(a),
    set: (a, s) => void entries.set(a, s),
  };
}

const saved = { ...process.env };

beforeEach(() => {
  delete process.env.BOTLOCK_MASTER_KEY;
  delete process.env.BOTLOCK_KEY_FILE;
  setKeychainBackend(null);
});

afterEach(() => {
  process.env = { ...saved };
  setKeychainBackend(undefined);
});

function rawState(dir: string) {
  return JSON.parse(readFileSync(statePath(dir), "utf8"));
}

describe("master key storage", () => {
  it("never writes the master key into state.json", () => {
    const dir = home();
    const state = loadState(dir);
    state.identity = createIdentity("t");
    state.secrets.api = sealSecret(state.masterKey!, "api", "sk_live_x", state.identity.id);
    saveState(state, dir);
    const text = readFileSync(statePath(dir), "utf8");
    expect(text).not.toContain(state.masterKey!);
    expect(rawState(dir)).not.toHaveProperty("masterKey");
    expect(rawState(dir)).not.toHaveProperty("keySource");
  });

  it("falls back to a separate 0600 key file and flags it in status", () => {
    const dir = home();
    const state = loadState(dir);
    expect(state.keySource).toBe("file");
    const path = keyFilePath(dir);
    expect(path).not.toBe(statePath(dir));
    expect(readFileSync(path, "utf8").trim()).toBe(state.masterKey);
    if (process.platform !== "win32") expect(statSync(path).mode & 0o777).toBe(0o600);
    expect(state.keyWarnings?.some((w) => /key file/i.test(w))).toBe(true);
    expect(evaluateStatus(state).findings.some((f) => /key file/i.test(f))).toBe(true);
    expect(loadState(dir).masterKey).toBe(state.masterKey);
  });

  it("tightens a key file that other users can read", () => {
    if (process.platform === "win32") return;
    const dir = home();
    const first = loadState(dir);
    chmodSync(keyFilePath(dir), 0o644);
    const again = loadState(dir);
    expect(again.masterKey).toBe(first.masterKey);
    expect(statSync(keyFilePath(dir)).mode & 0o777).toBe(0o600);
    expect(again.keyWarnings?.some((w) => /reset to 600/.test(w))).toBe(true);
  });

  it("honours BOTLOCK_KEY_FILE for a key file on another path", () => {
    const dir = home();
    const other = join(home(), "vault.key");
    process.env.BOTLOCK_KEY_FILE = other;
    const state = loadState(dir);
    expect(state.keyLocation).toBe(other);
    expect(existsSync(join(dir, "master.key"))).toBe(false);
    expect(readFileSync(other, "utf8").trim()).toBe(state.masterKey);
  });

  it("prefers BOTLOCK_MASTER_KEY and writes no key file", () => {
    const dir = home();
    process.env.BOTLOCK_MASTER_KEY = generateMasterKey();
    const state = loadState(dir);
    expect(state.keySource).toBe("env");
    expect(state.masterKey).toBe(process.env.BOTLOCK_MASTER_KEY);
    expect(existsSync(keyFilePath(dir))).toBe(false);
    expect(evaluateStatus(state).findings.some((f) => /key file/i.test(f))).toBe(false);
  });

  it("uses the OS keychain when one is available", () => {
    const dir = home();
    const kc = fakeKeychain();
    setKeychainBackend(kc);
    const state = loadState(dir);
    expect(state.keySource).toBe("keychain");
    expect(kc.entries.get(dir)).toBe(state.masterKey);
    expect(existsSync(keyFilePath(dir))).toBe(false);
    expect(loadState(dir).masterKey).toBe(state.masterKey);
  });

  it("falls back to a key file when the keychain throws", () => {
    const dir = home();
    setKeychainBackend({
      name: "broken keychain",
      available: () => true,
      get: () => undefined,
      set: () => {
        throw new Error("locked");
      },
    });
    const state = loadState(dir);
    expect(state.keySource).toBe("file");
    expect(state.keyWarnings?.some((w) => /broken keychain unavailable/.test(w))).toBe(true);
  });

  it("migrates a legacy state.json key out of the file and keeps secrets readable", () => {
    const dir = home();
    const legacy = generateMasterKey();
    const identity = createIdentity("legacy");
    const sealed = sealSecret(legacy, "gh", "ghs_legacy", identity.id);
    const first = loadState(dir); // creates a fresh state + key file
    writeFileSync(
      statePath(dir),
      JSON.stringify({ ...rawState(dir), identity, masterKey: legacy, secrets: { gh: sealed } }),
    );
    // Simulate a pre-fix install: no separate key file yet.
    unlinkSync(keyFilePath(dir));
    expect(first.masterKey).not.toBe(legacy);

    const migrated = loadState(dir);
    expect(migrated.masterKey).toBe(legacy);
    expect(rawState(dir)).not.toHaveProperty("masterKey");
    expect(readFileSync(keyFilePath(dir), "utf8").trim()).toBe(legacy);
    expect(openSecret(loadState(dir).masterKey!, loadState(dir).secrets.gh!)).toBe("ghs_legacy");
  });

  it("refuses to migrate when BOTLOCK_MASTER_KEY conflicts with the legacy key", () => {
    const dir = home();
    loadState(dir);
    writeFileSync(statePath(dir), JSON.stringify({ ...rawState(dir), masterKey: generateMasterKey() }));
    process.env.BOTLOCK_MASTER_KEY = generateMasterKey();
    expect(() => loadState(dir)).toThrow(/differs/);
  });

  it("does not mint a new key when sealed secrets exist but the key is gone", () => {
    const dir = home();
    const r = resolveMasterKey(dir, { hasSecrets: true });
    expect(r.masterKey).toBeUndefined();
    expect(r.source).toBe("none");
    expect(existsSync(keyFilePath(dir))).toBe(false);
  });
});
