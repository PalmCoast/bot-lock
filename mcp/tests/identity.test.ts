import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createIdentity, fingerprint, publicView, signMessage, verifyMessage } from "../src/identity.js";

describe("identity", () => {
  it("creates an Ed25519 identity with a stable public fingerprint", () => {
    const id = createIdentity("ops");
    expect(id.id).toHaveLength(16);
    expect(id.publicKeyPem).toContain("BEGIN PUBLIC KEY");
    expect(id.privateKeyPem).toContain("BEGIN PRIVATE KEY");
    expect(fingerprint(id.publicKeyPem)).toHaveLength(64);
    expect(publicView(id)).not.toHaveProperty("privateKeyPem");
  });

  it("signs and verifies messages; tampering fails", () => {
    const id = createIdentity();
    const sig = signMessage(id.privateKeyPem, "bot-lock-audit");
    expect(verifyMessage(id.publicKeyPem, "bot-lock-audit", sig)).toBe(true);
    expect(verifyMessage(id.publicKeyPem, "tampered", sig)).toBe(false);
  });

  it("does not collide two freshly generated identities", () => {
    const a = createIdentity();
    const b = createIdentity();
    expect(a.id).not.toBe(b.id);
    expect(a.publicKeyPem).not.toBe(b.publicKeyPem);
  });
});

export function tempHome(): string {
  return mkdtempSync(join(tmpdir(), "botlock-"));
}