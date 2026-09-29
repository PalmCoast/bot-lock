import { mkdirSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { resolveMasterKey, type KeySource } from "./keystore.js";
import { dirname, join } from "node:path";
import { homedir } from "node:os";
import type { AuditEntry, Policy, StoredIdentity } from "./types.js";
import type { SealedSecret } from "./vault.js";
import { defaultPolicy } from "./policy.js";

export type BotLockState = {
  identity?: StoredIdentity;
  /** In memory only. Never persisted to state.json. */
  masterKey?: string;
  /** Where masterKey came from (in memory only). */
  keySource?: KeySource;
  keyLocation?: string;
  keyWarnings?: string[];
  secrets: Record<string, SealedSecret>;
  audit: AuditEntry[];
  policy: Policy;
};

const EMPTY: BotLockState = {
  secrets: {},
  audit: [],
  policy: defaultPolicy(),
};

export function defaultHome(): string {
  return process.env.BOTLOCK_HOME?.replace(/^~/, homedir()) || join(homedir(), ".botlock");
}

export function statePath(home = defaultHome()): string {
  return join(home, "state.json");
}

const warned = new Set<string>();

function warnOnce(messages: string[]): void {
  for (const m of messages) {
    if (warned.has(m)) continue;
    warned.add(m);
    process.stderr.write(`${m}\n`);
  }
}

export function loadState(home = defaultHome()): BotLockState {
  const path = statePath(home);
  const exists = existsSync(path);
  const raw = exists ? (JSON.parse(readFileSync(path, "utf8")) as BotLockState) : undefined;
  const secrets = raw?.secrets ?? {};
  const legacyKey = raw?.masterKey;
  const key = resolveMasterKey(home, { legacyKey, hasSecrets: Object.keys(secrets).length > 0 });
  warnOnce(key.warnings);
  const state: BotLockState = {
    ...EMPTY,
    secrets,
    audit: raw?.audit ?? [],
    policy: raw?.policy ?? defaultPolicy(),
    identity: raw?.identity,
    masterKey: key.masterKey,
    keySource: key.source,
    keyLocation: key.location,
    keyWarnings: key.warnings,
  };
  // First run, or migrating a legacy state.json that still carries the key: rewrite without it.
  if (!exists || legacyKey) saveState(state, home);
  return state;
}

export function saveState(state: BotLockState, home = defaultHome()): void {
  const path = statePath(home);
  mkdirSync(dirname(path), { recursive: true });
  const { masterKey: _k, keySource: _s, keyLocation: _l, keyWarnings: _w, ...persisted } = state;
  writeFileSync(path, JSON.stringify(persisted, null, 2), { mode: 0o600 });
}

export function withState<T>(fn: (state: BotLockState) => T, home = defaultHome()): T {
  const state = loadState(home);
  const result = fn(state);
  saveState(state, home);
  return result;
}