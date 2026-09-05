import { mkdirSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { homedir } from "node:os";
import { defaultPolicy } from "./policy.js";
import { generateMasterKey } from "./vault.js";
const EMPTY = {
    secrets: {},
    audit: [],
    policy: defaultPolicy(),
};
export function defaultHome() {
    return process.env.BOTLOCK_HOME?.replace(/^~/, homedir()) || join(homedir(), ".botlock");
}
export function statePath(home = defaultHome()) {
    return join(home, "state.json");
}
export function loadState(home = defaultHome()) {
    const path = statePath(home);
    if (!existsSync(path)) {
        const state = {
            ...EMPTY,
            policy: defaultPolicy(),
            masterKey: process.env.BOTLOCK_MASTER_KEY || generateMasterKey(),
        };
        saveState(state, home);
        return state;
    }
    const raw = JSON.parse(readFileSync(path, "utf8"));
    return {
        secrets: raw.secrets ?? {},
        audit: raw.audit ?? [],
        policy: raw.policy ?? defaultPolicy(),
        identity: raw.identity,
        masterKey: raw.masterKey || process.env.BOTLOCK_MASTER_KEY || generateMasterKey(),
    };
}
export function saveState(state, home = defaultHome()) {
    const path = statePath(home);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, JSON.stringify(state, null, 2), { mode: 0o600 });
}
export function withState(fn, home = defaultHome()) {
    const state = loadState(home);
    const result = fn(state);
    saveState(state, home);
    return result;
}
