import type { Policy, ScopeDecision, ScopeRequest, ToolAction } from "./types.js";

const DESTRUCTIVE = [
  "delete",
  "rm",
  "drop",
  "destroy",
  "wipe",
  "transfer",
  "pay",
  "charge",
  "deploy",
  "email_all",
  "broadcast",
  "chmod",
  "chown",
];

export function defaultPolicy(): Policy {
  return {
    version: 1,
    name: "deny-by-default",
    killSwitch: { engaged: false },
    tools: {
      default: "deny",
      allow: [],
      deny: ["shell", "exec", "bash", "eval"],
    },
    mcp: { default: "deny", allow: [{ name: "bot-lock" }] },
    secrets: {
      requireVault: true,
      forbidEnvDump: true,
      allowPrefixes: ["BOTLOCK_", "APP_"],
    },
    autonomy: {
      maxSteps: 12,
      requireHumanFor: ["pay", "deploy", "email", "delete"],
      noUnattendedDestructive: true,
      forbidSelfPrivilegeEscalation: true,
    },
    io: {
      inboundScan: true,
      outboundScan: true,
      denyPatterns: [
        "ignore (all )?previous instructions",
        "exfiltrate",
        "dump (the )?(env|secrets|tokens)",
        "-----BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY-----",
      ],
    },
    oauth: {
      noTokenDelegationToUntrusted: true,
      maxTokenTtlHours: 8,
      agentOwnsClient: true,
    },
    exfil: {
      denyDestinations: [],
      allowDestinations: [],
      maxOutboundBytes: 256_000,
    },
  };
}

export function checkScope(policy: Policy, request: ScopeRequest): ScopeDecision {
  if (policy.killSwitch.engaged) {
    return {
      allowed: false,
      action: "deny",
      reason: `Kill switch engaged${policy.killSwitch.reason ? `: ${policy.killSwitch.reason}` : "."}`,
      matchedRule: "killSwitch",
      killSwitch: true,
    };
  }

  const tool = request.tool.trim();
  if (!tool) {
    return deny("Tool name is required.", "tools");
  }

  if (policy.autonomy.forbidSelfPrivilegeEscalation && looksLikePrivilegeEscalation(tool, request.inputText)) {
    return deny("Policy forbids the agent from expanding its own permissions.", "autonomy.forbidSelfPrivilegeEscalation");
  }

  if (request.step !== undefined && request.step > policy.autonomy.maxSteps) {
    return deny(`Step ${request.step} exceeds autonomy.maxSteps (${policy.autonomy.maxSteps}).`, "autonomy.maxSteps");
  }

  if (request.mcpServer && policy.mcp.default === "deny") {
    const allowedServer = policy.mcp.allow.some((s) => s.name === request.mcpServer);
    if (!allowedServer) {
      return deny(`MCP server "${request.mcpServer}" is not on the allowlist.`, "mcp.allow");
    }
  }

  const denied = policy.tools.deny.find((name) => matchName(name, tool));
  if (denied) {
    return deny(`Tool "${tool}" is explicitly denied.`, "tools.deny");
  }

  if (policy.io.inboundScan && request.inputText && hitsDenyPattern(policy.io.denyPatterns, request.inputText)) {
    return confirmOrDeny(
      policy,
      tool,
      "Inbound text matched an I/O deny-pattern (possible injection or secret leak).",
      "io.inboundScan",
    );
  }

  if (policy.io.outboundScan && request.outputText && hitsDenyPattern(policy.io.denyPatterns, request.outputText)) {
    return deny("Outbound text matched an I/O deny-pattern.", "io.outboundScan");
  }

  if (request.destination) {
    const dest = request.destination.toLowerCase();
    if (policy.exfil.denyDestinations.some((d) => dest.includes(d.toLowerCase()))) {
      return deny(`Destination "${request.destination}" is blocked by exfil policy.`, "exfil.denyDestinations");
    }
    if (
      policy.exfil.allowDestinations.length > 0 &&
      !policy.exfil.allowDestinations.some((d) => dest.includes(d.toLowerCase()))
    ) {
      return deny(`Destination "${request.destination}" is not on the exfil allowlist.`, "exfil.allowDestinations");
    }
  }

  const outbound = request.outboundBytes ?? 0;
  const rule = policy.tools.allow.find((r) => matchName(r.name, tool));
  const maxBytes = rule?.maxOutboundBytes ?? policy.exfil.maxOutboundBytes;
  if (outbound > maxBytes) {
    return deny(`Outbound payload ${outbound} bytes exceeds max ${maxBytes}.`, "exfil.maxOutboundBytes");
  }

  const humanRequired = policy.autonomy.requireHumanFor.some((verb) => tool.toLowerCase().includes(verb.toLowerCase()));
  const destructive = policy.autonomy.noUnattendedDestructive && looksDestructive(tool);

  if (rule) {
    if (rule.requiresConfirm || humanRequired || destructive) {
      return {
        allowed: false,
        action: "confirm",
        reason: "Policy requires a human confirmation before this tool may run.",
        matchedRule: rule.name,
        killSwitch: false,
      };
    }
    return {
      allowed: true,
      action: "allow",
      reason: `Allowlisted tool "${rule.name}".`,
      matchedRule: rule.name,
      killSwitch: false,
    };
  }

  if (humanRequired || destructive) {
    return {
      allowed: false,
      action: "confirm",
      reason: "Destructive or high-impact action requires a human.",
      matchedRule: "autonomy.requireHumanFor",
      killSwitch: false,
    };
  }

  return fromDefault(policy.tools.default, tool);
}

function fromDefault(action: ToolAction, tool: string): ScopeDecision {
  if (action === "allow") {
    return { allowed: true, action, reason: `Default allow for "${tool}".`, matchedRule: "tools.default", killSwitch: false };
  }
  if (action === "confirm") {
    return { allowed: false, action, reason: `Default confirm for "${tool}".`, matchedRule: "tools.default", killSwitch: false };
  }
  return deny(`Tool "${tool}" is not allowlisted (deny-by-default).`, "tools.default");
}

function confirmOrDeny(policy: Policy, tool: string, reason: string, matchedRule: string): ScopeDecision {
  const rule = policy.tools.allow.find((r) => matchName(r.name, tool));
  if (rule) {
    return { allowed: false, action: "confirm", reason, matchedRule, killSwitch: false };
  }
  return deny(reason, matchedRule);
}

function deny(reason: string, matchedRule: string): ScopeDecision {
  return { allowed: false, action: "deny", reason, matchedRule, killSwitch: false };
}

function matchName(pattern: string, tool: string): boolean {
  if (pattern === tool) return true;
  if (pattern.endsWith("*")) return tool.startsWith(pattern.slice(0, -1));
  return pattern.toLowerCase() === tool.toLowerCase();
}

function hitsDenyPattern(patterns: string[], text: string): boolean {
  return patterns.some((p) => {
    try {
      return new RegExp(p, "i").test(text);
    } catch {
      return text.toLowerCase().includes(p.toLowerCase());
    }
  });
}

function looksDestructive(tool: string): boolean {
  const t = tool.toLowerCase();
  return DESTRUCTIVE.some((verb) => t.includes(verb));
}

function looksLikePrivilegeEscalation(tool: string, input?: string): boolean {
  const blob = `${tool} ${input ?? ""}`.toLowerCase();
  return (
    blob.includes("add tool") ||
    blob.includes("grant scope") ||
    blob.includes("sudo") ||
    blob.includes("chmod 777") ||
    blob.includes("new oauth") ||
    blob.includes("elevate")
  );
}

export function engageKillSwitch(policy: Policy, reason: string): Policy {
  return {
    ...policy,
    killSwitch: {
      engaged: true,
      reason,
      engagedAt: new Date().toISOString(),
    },
  };
}

export function releaseKillSwitch(policy: Policy): Policy {
  return {
    ...policy,
    killSwitch: { engaged: false },
  };
}