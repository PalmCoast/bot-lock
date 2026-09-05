# Bot Lock — Claude Code / MCP install guide

For operators who bought **Pro ($149)** or who are running this repo locally.

## 1. Build

```bash
git clone <this-repo>
cd mcp
npm install
npm test
npm run build
```

Confirm Node 20+. The binary is `mcp/dist/index.js`.

## 2. Claude Code

Add to `.claude/settings.json` (project) or `~/.claude.json` (user):

```json
{
  "mcpServers": {
    "bot-lock": {
      "command": "node",
      "args": ["/ABS/PATH/TO/mcp/dist/index.js"],
      "env": {
        "BOTLOCK_HOME": "/ABS/PATH/TO/.botlock",
        "BOTLOCK_MASTER_KEY": "paste-or-leave-unset-to-auto-generate"
      }
    }
  }
}
```

Restart Claude Code. Ask: “Call `botlock_status` and summarize findings.”

Then, in this order:

1. `botlock_identity_create` with a label like `prod-writer`
2. `botlock_policy_load` with a Field Kit policy JSON (`policies/combined.example.json`)
3. `botlock_vault_put` for each production secret — do not paste secrets into the system prompt
4. Before any other MCP tool, `botlock_scope_check`

## 3. Cursor

In Cursor MCP settings (`mcp.json`):

```json
{
  "mcpServers": {
    "bot-lock": {
      "command": "node",
      "args": ["/ABS/PATH/TO/mcp/dist/index.js"],
      "env": {
        "BOTLOCK_HOME": "/ABS/PATH/TO/.botlock"
      }
    }
  }
}
```

## 4. Wire the gate (required)

Bot Lock cannot interpose on tools it does not see. Add a standing instruction to the agent:

> Before calling any tool other than Bot Lock, call `botlock_scope_check` with the tool name, destination, and a short excerpt of untrusted input. If the decision is `deny`, stop. If `confirm`, ask me. If the kill switch is engaged, stop the task and notify me.

Without that instruction, you have a vault and a log — not a gate.

## 5. Kill switch

```
botlock_kill_switch { "engage": true, "reason": "suspected prompt injection" }
```

Follow `policies/kill-switch-runbook.md` for credential revoke and process halt. Releasing the switch is an explicit operator action.

## 6. Limits

This package does not sandbox the model, intercept raw syscalls, or replace your cloud IAM. Pair it with least-privilege cloud keys, an MCP allowlist, and the playbook verification steps.