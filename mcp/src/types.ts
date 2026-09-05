export type ToolAction = "allow" | "deny" | "confirm";

export type ToolRule = {
  name: string;
  scopes?: string[];
  maxCallsPerHour?: number;
  requiresConfirm?: boolean;
  maxOutboundBytes?: number;
};

export type McpRule = {
  name: string;
  command?: string;
  sha256?: string;
};

export type Policy = {
  version: 1;
  name: string;
  killSwitch: {
    engaged: boolean;
    reason?: string;
    engagedAt?: string;
  };
  tools: {
    default: ToolAction;
    allow: ToolRule[];
    deny: string[];
  };
  mcp: {
    default: "deny" | "allow";
    allow: McpRule[];
  };
  secrets: {
    requireVault: boolean;
    forbidEnvDump: boolean;
    allowPrefixes: string[];
  };
  autonomy: {
    maxSteps: number;
    requireHumanFor: string[];
    noUnattendedDestructive: boolean;
    forbidSelfPrivilegeEscalation: boolean;
  };
  io: {
    inboundScan: boolean;
    outboundScan: boolean;
    denyPatterns: string[];
  };
  oauth: {
    noTokenDelegationToUntrusted: boolean;
    maxTokenTtlHours: number;
    agentOwnsClient: boolean;
  };
  exfil: {
    denyDestinations: string[];
    allowDestinations: string[];
    maxOutboundBytes: number;
  };
};

export type IdentityRecord = {
  id: string;
  label: string;
  publicKeyPem: string;
  createdAt: string;
};

export type StoredIdentity = IdentityRecord & {
  privateKeyPem: string;
};

export type VaultMeta = {
  name: string;
  createdAt: string;
  updatedAt: string;
  identityId: string;
};

export type AuditEntry = {
  seq: number;
  ts: string;
  actor: string;
  action: string;
  payloadHash: string;
  prevHash: string;
  hash: string;
  signature: string;
};

export type ScopeRequest = {
  tool: string;
  mcpServer?: string;
  destination?: string;
  outboundBytes?: number;
  inputText?: string;
  outputText?: string;
  step?: number;
};

export type ScopeDecision = {
  allowed: boolean;
  action: ToolAction;
  reason: string;
  matchedRule?: string;
  killSwitch: boolean;
};

export type ControlStatus = {
  identityReady: boolean;
  identityId?: string;
  vaultUnlocked: boolean;
  secretCount: number;
  auditValid: boolean;
  auditLength: number;
  policyLoaded: boolean;
  policyName?: string;
  killSwitch: boolean;
  findings: string[];
};