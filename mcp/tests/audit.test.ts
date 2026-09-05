import { describe, expect, it } from "vitest";
import { GENESIS_HASH, appendAudit, payloadDigest, verifyChain } from "../src/audit.js";
import { createIdentity } from "../src/identity.js";

describe("audit chain", () => {
  it("links entries from genesis and verifies signatures", () => {
    const id = createIdentity();
    const chain = [];
    const a = appendAudit({ chain, actor: id.id, action: "boot", payload: { ok: true }, privateKeyPem: id.privateKeyPem });
    chain.push(a);
    const b = appendAudit({ chain, actor: id.id, action: "vault.put", payload: { name: "x" }, privateKeyPem: id.privateKeyPem });
    chain.push(b);

    expect(a.prevHash).toBe(GENESIS_HASH);
    expect(b.prevHash).toBe(a.hash);
    expect(b.seq).toBe(2);
    expect(verifyChain(chain, id.publicKeyPem)).toEqual({ valid: true });
  });

  it("detects a spliced hash", () => {
    const id = createIdentity();
    const chain = [];
    chain.push(appendAudit({ chain, actor: id.id, action: "a", payload: {}, privateKeyPem: id.privateKeyPem }));
    chain.push(appendAudit({ chain, actor: id.id, action: "b", payload: {}, privateKeyPem: id.privateKeyPem }));
    chain[1] = { ...chain[1]!, action: "evil" };
    const result = verifyChain(chain, id.publicKeyPem);
    expect(result.valid).toBe(false);
    expect(result.brokenAt).toBe(2);
  });

  it("detects a foreign signature", () => {
    const a = createIdentity();
    const b = createIdentity();
    const chain = [];
    chain.push(appendAudit({ chain, actor: a.id, action: "a", payload: {}, privateKeyPem: a.privateKeyPem }));
    expect(verifyChain(chain, b.publicKeyPem).valid).toBe(false);
  });

  it("hashes payloads stably regardless of key order", () => {
    expect(payloadDigest({ b: 1, a: 2 })).toBe(payloadDigest({ a: 2, b: 1 }));
  });
});