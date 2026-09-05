import { createHash, generateKeyPairSync, sign as cryptoSign, verify as cryptoVerify } from "node:crypto";
import type { StoredIdentity } from "./types.js";

export function createIdentity(label = "default"): StoredIdentity {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const id = createHash("sha256").update(publicKeyPem).digest("hex").slice(0, 16);
  return {
    id,
    label,
    publicKeyPem,
    privateKeyPem,
    createdAt: new Date().toISOString(),
  };
}

export function publicView(identity: StoredIdentity) {
  return {
    id: identity.id,
    label: identity.label,
    publicKeyPem: identity.publicKeyPem,
    createdAt: identity.createdAt,
  };
}

export function signMessage(privateKeyPem: string, message: string | Buffer): string {
  const data = typeof message === "string" ? Buffer.from(message, "utf8") : message;
  return cryptoSign(null, data, privateKeyPem).toString("base64");
}

export function verifyMessage(publicKeyPem: string, message: string | Buffer, signatureB64: string): boolean {
  const data = typeof message === "string" ? Buffer.from(message, "utf8") : message;
  try {
    return cryptoVerify(null, data, publicKeyPem, Buffer.from(signatureB64, "base64"));
  } catch {
    return false;
  }
}

export function fingerprint(publicKeyPem: string): string {
  return createHash("sha256").update(publicKeyPem).digest("hex");
}