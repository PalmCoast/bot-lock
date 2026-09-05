import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { appendAudit } from "../src/audit.js";
import { createIdentity } from "../src/identity.js";
import { defaultPolicy } from "../src/policy.js";
import { evaluateStatus } from "../src/status.js";
import { loadState, saveState } from "../src/store.js";
import { generateMasterKey, sealSecret } from "../src/vault.js";

function home() {
  return mkdtempSync(join(tmpdir(), "botlock-"));
}

describe("status and store", () => {
  it("reports missing identity as a finding", () => {
    const state = loadState(home());
    const status = evaluateStatus(state);
    expect(status.identityReady).toBe(false);
    expect(status.findings.some((f) => /identity/i.test(f))).toBe(true);
    expect(status.auditValid).toBe(true);
  });

  it("persists identity, vault metadata, and a valid audit chain", () => {
    const dir = home();
    const state = loadState(dir);
    state.identity = createIdentity("prod");
    state.masterKey = generateMasterKey();
    state.secrets.gh = sealSecret(state.masterKey, "gh", "ghs_test", state.identity.id);
    state.audit.push(
      appendAudit({
        chain: state.audit,
        actor: state.identity.id,
        action: "vault.put",
        payload: { name: "gh" },
        privateKeyPem: state.identity.privateKeyPem,
      }),
    );
    saveState(state, dir);

    const reloaded = loadState(dir);
    const status = evaluateStatus(reloaded);
    expect(status.identityReady).toBe(true);
    expect(status.identityId).toBe(state.identity.id);
    expect(status.secretCount).toBe(1);
    expect(status.auditValid).toBe(true);
    expect(status.auditLength).toBe(1);
    expect(reloaded.secrets.gh).toBeDefined();
    expect(JSON.stringify(reloaded.secrets.gh)).not.toContain("ghs_test");
  });

  it("flags a permissive tool default", () => {
    const state = loadState(home());
    state.policy = { ...defaultPolicy(), tools: { default: "allow", allow: [], deny: [] } };
    const status = evaluateStatus(state);
    expect(status.findings.some((f) => /deny-by-default/i.test(f))).toBe(true);
  });
});