import { createCipheriv, createDecipheriv, createHash, randomBytes, scryptSync } from "node:crypto";
import type { VaultMeta } from "./types.js";

const ALGO = "aes-256-gcm";
const KEY_LEN = 32;
const IV_LEN = 12;
const SALT_LEN = 16;

export type SealedSecret = VaultMeta & {
  ciphertext: string;
  iv: string;
  tag: string;
  salt: string;
};

export function deriveKey(masterKey: string, salt: Buffer): Buffer {
  return scryptSync(masterKey, salt, KEY_LEN);
}

export function sealSecret(
  masterKey: string,
  name: string,
  plaintext: string,
  identityId: string,
): SealedSecret {
  if (!name.trim()) throw new Error("Secret name is required.");
  if (!plaintext) throw new Error("Secret value is required.");
  const salt = randomBytes(SALT_LEN);
  const iv = randomBytes(IV_LEN);
  const key = deriveKey(masterKey, salt);
  const cipher = createCipheriv(ALGO, key, iv);
  const enc = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  const now = new Date().toISOString();
  return {
    name,
    identityId,
    createdAt: now,
    updatedAt: now,
    ciphertext: enc.toString("base64"),
    iv: iv.toString("base64"),
    tag: tag.toString("base64"),
    salt: salt.toString("base64"),
  };
}

export function openSecret(masterKey: string, sealed: SealedSecret): string {
  const key = deriveKey(masterKey, Buffer.from(sealed.salt, "base64"));
  const decipher = createDecipheriv(ALGO, key, Buffer.from(sealed.iv, "base64"));
  decipher.setAuthTag(Buffer.from(sealed.tag, "base64"));
  const dec = Buffer.concat([
    decipher.update(Buffer.from(sealed.ciphertext, "base64")),
    decipher.final(),
  ]);
  return dec.toString("utf8");
}

export function secretFingerprint(plaintext: string): string {
  return createHash("sha256").update(plaintext).digest("hex").slice(0, 12);
}

export function publicMeta(sealed: SealedSecret): VaultMeta {
  return {
    name: sealed.name,
    createdAt: sealed.createdAt,
    updatedAt: sealed.updatedAt,
    identityId: sealed.identityId,
  };
}

export function generateMasterKey(): string {
  return randomBytes(32).toString("base64");
}