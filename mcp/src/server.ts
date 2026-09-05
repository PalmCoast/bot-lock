import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { appendAudit, verifyChain } from "./audit.js";
import { createIdentity, publicView } from "./identity.js";
import { engageKillSwitch, checkScope, defaultPolicy, releaseKillSwitch } from "./policy.js";
import { evaluateStatus } from "./status.js";
import { loadState, saveState, defaultHome } from "./store.js";
import { openSecret, publicMeta, sealSecret } from "./vault.js";
import type { Policy } from "./types.js";

function text(data: unknown) {
  return {
    content: [{ type: "text" as const, text: typeof data === "string" ? data : JSON.stringify(data, null, 2) }],
  };
}

function record(state: ReturnType<typeof loadState>, action: string, payload: unknown) {
  if (!state.identity) return;
  const entry = appendAudit({
    chain: state.audit,
    actor: state.identity.id,
    action,
    payload,
    privateKeyPem: state.identity.privateKeyPem,
  });
  state.audit.push(entry);
}

export function createBotLockServer(home = defaultHome()) {
  const server = new McpServer({
    name: "bot-lock",
    version: "1.0.0",
  });

  server.tool(
    "botlock_status",
    "Return Bot Lock control-plane status: identity, vault, audit chain, policy, kill switch, and findings.",
    {},
    async () => {
      const state = loadState(home);
      return text(evaluateStatus(state));
    },
  );

  server.tool(
    "botlock_identity_create",
    "Create or rotate the local Ed25519 agent identity used to sign the audit chain. Rotation keeps the old key out of the new chain.",
    { label: z.string().optional(), rotate: z.boolean().optional() },
    async ({ label, rotate }) => {
      const state = loadState(home);
      if (state.identity && !rotate) {
        return text({ created: false, identity: publicView(state.identity), note: "Identity already exists. Pass rotate=true to replace it." });
      }
      state.identity = createIdentity(label ?? "default");
      if (rotate) state.audit = [];
      record(state, "identity.create", { id: state.identity.id, label: state.identity.label, rotate: Boolean(rotate) });
      saveState(state, home);
      return text({ created: true, identity: publicView(state.identity) });
    },
  );

  server.tool(
    "botlock_identity_show",
    "Show the public agent identity (never the private key).",
    {},
    async () => {
      const state = loadState(home);
      if (!state.identity) return text({ error: "No identity. Call botlock_identity_create." });
      return text(publicView(state.identity));
    },
  );

  server.tool(
    "botlock_vault_put",
    "Seal a secret into the AES-GCM vault. The plaintext is not written to the audit log.",
    {
      name: z.string(),
      value: z.string(),
    },
    async ({ name, value }) => {
      const state = loadState(home);
      if (!state.masterKey) return text({ error: "Vault master key missing." });
      if (!state.identity) return text({ error: "Create an identity first." });
      const sealed = sealSecret(state.masterKey, name, value, state.identity.id);
      if (state.secrets[name]) sealed.createdAt = state.secrets[name]!.createdAt;
      state.secrets[name] = sealed;
      record(state, "vault.put", { name, identityId: state.identity.id });
      saveState(state, home);
      return text({ stored: true, secret: publicMeta(sealed) });
    },
  );

  server.tool(
    "botlock_vault_get",
    "Open a named secret. Use only when the current task needs it. The value is returned to the caller and is not appended to the audit payload.",
    { name: z.string() },
    async ({ name }) => {
      const state = loadState(home);
      if (!state.masterKey) return text({ error: "Vault master key missing." });
      const sealed = state.secrets[name];
      if (!sealed) return text({ error: `No secret named "${name}".` });
      const value = openSecret(state.masterKey, sealed);
      record(state, "vault.get", { name });
      saveState(state, home);
      return text({ name, value });
    },
  );

  server.tool(
    "botlock_vault_list",
    "List vault secret names and metadata. Values are not returned.",
    {},
    async () => {
      const state = loadState(home);
      return text(Object.values(state.secrets).map(publicMeta));
    },
  );

  server.tool(
    "botlock_audit_append",
    "Append a signed, hash-chained audit event. Put only non-secret metadata in payload.",
    {
      action: z.string(),
      payload: z.record(z.unknown()).optional(),
    },
    async ({ action, payload }) => {
      const state = loadState(home);
      if (!state.identity) return text({ error: "Create an identity first." });
      record(state, action, payload ?? {});
      saveState(state, home);
      return text(state.audit[state.audit.length - 1]);
    },
  );

  server.tool(
    "botlock_audit_tail",
    "Return the latest N audit entries (hashes and actions, not secret values).",
    { limit: z.number().int().min(1).max(200).optional() },
    async ({ limit }) => {
      const state = loadState(home);
      const n = limit ?? 20;
      return text(state.audit.slice(-n));
    },
  );

  server.tool(
    "botlock_audit_verify",
    "Verify the hash chain and Ed25519 signatures on the local audit log.",
    {},
    async () => {
      const state = loadState(home);
      if (!state.identity) return text({ valid: state.audit.length === 0, reason: "No identity." });
      return text(verifyChain(state.audit, state.identity.publicKeyPem));
    },
  );

  server.tool(
    "botlock_scope_check",
    "Ask Bot Lock whether a tool call is allowed, denied, or needs a human confirmation under the loaded policy.",
    {
      tool: z.string(),
      mcpServer: z.string().optional(),
      destination: z.string().optional(),
      outboundBytes: z.number().int().nonnegative().optional(),
      inputText: z.string().optional(),
      outputText: z.string().optional(),
      step: z.number().int().positive().optional(),
    },
    async (request) => {
      const state = loadState(home);
      const decision = checkScope(state.policy, request);
      record(state, "scope.check", { tool: request.tool, action: decision.action, reason: decision.reason });
      saveState(state, home);
      return text(decision);
    },
  );

  server.tool(
    "botlock_policy_show",
    "Show the active policy document.",
    {},
    async () => {
      const state = loadState(home);
      return text(state.policy);
    },
  );

  server.tool(
    "botlock_policy_load",
    "Replace the active policy with a JSON policy document (version 1).",
    { policy: z.record(z.unknown()) },
    async ({ policy }) => {
      const state = loadState(home);
      const next = policy as unknown as Policy;
      if (next.version !== 1 || !next.name || !next.tools || !next.killSwitch) {
        return text({ error: "Invalid policy. Expected version 1 with name, tools, and killSwitch." });
      }
      state.policy = next;
      record(state, "policy.load", { name: next.name });
      saveState(state, home);
      return text({ loaded: true, name: next.name });
    },
  );

  server.tool(
    "botlock_policy_reset",
    "Reset policy to the built-in deny-by-default template.",
    {},
    async () => {
      const state = loadState(home);
      state.policy = defaultPolicy();
      record(state, "policy.reset", { name: state.policy.name });
      saveState(state, home);
      return text(state.policy);
    },
  );

  server.tool(
    "botlock_kill_switch",
    "Engage or release the kill switch. When engaged, every scope check is denied.",
    {
      engage: z.boolean(),
      reason: z.string().optional(),
    },
    async ({ engage, reason }) => {
      const state = loadState(home);
      state.policy = engage
        ? engageKillSwitch(state.policy, reason ?? "operator halt")
        : releaseKillSwitch(state.policy);
      record(state, engage ? "kill.engage" : "kill.release", { reason: reason ?? null });
      saveState(state, home);
      return text({ killSwitch: state.policy.killSwitch });
    },
  );

  return server;
}
