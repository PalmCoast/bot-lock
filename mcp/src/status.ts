import { verifyChain } from "./audit.js";
import type { BotLockState } from "./store.js";
import type { ControlStatus } from "./types.js";

export function evaluateStatus(state: BotLockState): ControlStatus {
  const findings: string[] = [];
  const identityReady = Boolean(state.identity);
  if (!identityReady) findings.push("No agent identity. Create one before signing audit entries.");

  const vaultUnlocked = Boolean(state.masterKey);
  if (!vaultUnlocked) findings.push("Vault master key is missing.");

  const secretCount = Object.keys(state.secrets).length;
  if (state.policy.secrets.requireVault && secretCount === 0) {
    findings.push("Policy requires a vault, but no secrets are stored yet.");
  }

  let auditValid = true;
  if (!state.identity) {
    auditValid = state.audit.length === 0;
    if (state.audit.length > 0) findings.push("Audit entries exist without a signing identity.");
  } else {
    const check = verifyChain(state.audit, state.identity.publicKeyPem);
    auditValid = check.valid;
    if (!check.valid) findings.push(`Audit chain invalid at seq ${check.brokenAt}: ${check.reason}`);
  }

  const policyLoaded = Boolean(state.policy?.name);
  if (state.policy.tools.default !== "deny") {
    findings.push("Tool default is not deny-by-default. New tools will run without review.");
  }
  if (state.policy.mcp.default !== "deny") {
    findings.push("MCP default is not deny. Unpinned servers can attach.");
  }
  if (!state.policy.killSwitch.engaged && !state.policy.autonomy.noUnattendedDestructive) {
    findings.push("Unattended destructive actions are allowed.");
  }
  if (state.policy.killSwitch.engaged) {
    findings.push(`Kill switch is engaged${state.policy.killSwitch.reason ? `: ${state.policy.killSwitch.reason}` : "."}`);
  }

  return {
    identityReady,
    identityId: state.identity?.id,
    vaultUnlocked,
    secretCount,
    auditValid,
    auditLength: state.audit.length,
    policyLoaded,
    policyName: state.policy?.name,
    killSwitch: state.policy.killSwitch.engaged,
    findings,
  };
}