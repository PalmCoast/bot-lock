import { mkdirSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { homedir } from "node:os";
import type { AuditEntry, Policy, StoredIdentity } from "./types.js";
import type { SealedSecret } from "./vault.js";
import { defaultPolicy } from "./policy.js";
import { generateMasterKey } from "./vault.js";

export type BotLockState = {
  identity?: StoredIdentity;
  masterKey?: string;
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

export function loadState(home = defaultHome()): BotLockState {
  const path = statePath(home);
  if (!existsSync(path)) {
    const state: BotLockState = {
      ...EMPTY,
      policy: defaultPolicy(),
      masterKey: process.env.BOTLOCK_MASTER_KEY || generateMasterKey(),
    };
    saveState(state, home);
    return state;
  }
  const raw = JSON.parse(readFileSync(path, "utf8")) as BotLockState;
  return {
    secrets: raw.secrets ?? {},
    audit: raw.audit ?? [],
    policy: raw.policy ?? defaultPolicy(),
    identity: raw.identity,
    masterKey: raw.masterKey || process.env.BOTLOCK_MASTER_KEY || generateMasterKey(),
  };
}

export function saveState(state: BotLockState, home = defaultHome()): void {
  const path = statePath(home);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(state, null, 2), { mode: 0o600 });
}

export function withState<T>(fn: (state: BotLockState) => T, home = defaultHome()): T {
  const state = loadState(home);
  const result = fn(state);
  saveState(state, home);
  return result;
}