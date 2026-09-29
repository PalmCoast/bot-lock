import { mkdirSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { resolveMasterKey } from "./keystore.js";
import { dirname, join } from "node:path";
import { homedir } from "node:os";
import { defaultPolicy } from "./policy.js";
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
const warned = new Set();
function warnOnce(messages) {
    for (const m of messages) {
        if (warned.has(m))
            continue;
        warned.add(m);
        process.stderr.write(`${m}\n`);
    }
}
export function loadState(home = defaultHome()) {
    const path = statePath(home);
    const exists = existsSync(path);
    const raw = exists ? JSON.parse(readFileSync(path, "utf8")) : undefined;
    const secrets = raw?.secrets ?? {};
    const legacyKey = raw?.masterKey;
    const key = resolveMasterKey(home, { legacyKey, hasSecrets: Object.keys(secrets).length > 0 });
    warnOnce(key.warnings);
    const state = {
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
    if (!exists || legacyKey)
        saveState(state, home);
    return state;
}
export function saveState(state, home = defaultHome()) {
    const path = statePath(home);
    mkdirSync(dirname(path), { recursive: true });
    const { masterKey: _k, keySource: _s, keyLocation: _l, keyWarnings: _w, ...persisted } = state;
    writeFileSync(path, JSON.stringify(persisted, null, 2), { mode: 0o600 });
}
export function withState(fn, home = defaultHome()) {
    const state = loadState(home);
    const result = fn(state);
    saveState(state, home);
    return result;
}
