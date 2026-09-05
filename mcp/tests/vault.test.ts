import { describe, expect, it } from "vitest";
import { generateMasterKey, openSecret, publicMeta, sealSecret } from "../src/vault.js";

describe("vault", () => {
  it("round-trips a secret with AES-GCM", () => {
    const master = generateMasterKey();
    const sealed = sealSecret(master, "stripe", "sk_test_secret", "agent-1");
    expect(sealed.ciphertext).not.toContain("sk_test");
    expect(openSecret(master, sealed)).toBe("sk_test_secret");
    expect(publicMeta(sealed)).toMatchObject({ name: "stripe", identityId: "agent-1" });
    expect(publicMeta(sealed)).not.toHaveProperty("ciphertext");
  });

  it("rejects a wrong master key", () => {
    const sealed = sealSecret(generateMasterKey(), "token", "abc", "a");
    expect(() => openSecret(generateMasterKey(), sealed)).toThrow();
  });

  it("rejects tampered ciphertext", () => {
    const master = generateMasterKey();
    const sealed = sealSecret(master, "x", "plain", "a");
    const broken = { ...sealed, ciphertext: Buffer.from("nope").toString("base64") };
    expect(() => openSecret(master, broken)).toThrow();
  });

  it("requires a name and value", () => {
    const master = generateMasterKey();
    expect(() => sealSecret(master, " ", "v", "a")).toThrow(/name/i);
    expect(() => sealSecret(master, "n", "", "a")).toThrow(/value/i);
  });
});