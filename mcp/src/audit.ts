import { createHash } from "node:crypto";
import { signMessage, verifyMessage } from "./identity.js";
import type { AuditEntry } from "./types.js";

export const GENESIS_HASH = "0".repeat(64);

export function payloadDigest(payload: unknown): string {
  const json = stableStringify(payload);
  return createHash("sha256").update(json).digest("hex");
}

export function computeHash(input: {
  seq: number;
  ts: string;
  actor: string;
  action: string;
  payloadHash: string;
  prevHash: string;
}): string {
  const canonical = `${input.seq}|${input.ts}|${input.actor}|${input.action}|${input.payloadHash}|${input.prevHash}`;
  return createHash("sha256").update(canonical).digest("hex");
}

export function appendAudit(args: {
  chain: AuditEntry[];
  actor: string;
  action: string;
  payload: unknown;
  privateKeyPem: string;
}): AuditEntry {
  const prevHash = args.chain.length === 0 ? GENESIS_HASH : args.chain[args.chain.length - 1]!.hash;
  const seq = args.chain.length + 1;
  const ts = new Date().toISOString();
  const payloadHash = payloadDigest(args.payload);
  const hash = computeHash({
    seq,
    ts,
    actor: args.actor,
    action: args.action,
    payloadHash,
    prevHash,
  });
  const signature = signMessage(args.privateKeyPem, hash);
  return { seq, ts, actor: args.actor, action: args.action, payloadHash, prevHash, hash, signature };
}

export function verifyChain(
  chain: AuditEntry[],
  publicKeyPem: string,
): { valid: boolean; brokenAt?: number; reason?: string } {
  let expectedPrev = GENESIS_HASH;
  for (const entry of chain) {
    if (entry.prevHash !== expectedPrev) {
      return { valid: false, brokenAt: entry.seq, reason: "prevHash does not match previous entry." };
    }
    const expectedHash = computeHash({
      seq: entry.seq,
      ts: entry.ts,
      actor: entry.actor,
      action: entry.action,
      payloadHash: entry.payloadHash,
      prevHash: entry.prevHash,
    });
    if (expectedHash !== entry.hash) {
      return { valid: false, brokenAt: entry.seq, reason: "Entry hash mismatch." };
    }
    if (!verifyMessage(publicKeyPem, entry.hash, entry.signature)) {
      return { valid: false, brokenAt: entry.seq, reason: "Signature verification failed." };
    }
    expectedPrev = entry.hash;
  }
  return { valid: true };
}

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((v) => stableStringify(v)).join(",")}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(obj[k])}`).join(",")}}`;
}