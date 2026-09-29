# Bot Lock — Claude Code / MCP install guide

The Bot Lock MCP server is **free and MIT-licensed**. You do not need to buy anything to run it.
The paid Field Kit ($49) and Pro ($149) at https://bot-lock.netlify.app/#pricing are the playbook and policy templates that go with it (see "Upgrade" at the end).

## 1. Build

```bash
git clone https://github.com/PalmCoast/bot-lock.git
cd bot-lock/mcp
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
        "BOTLOCK_HOME": "/ABS/PATH/TO/.botlock"
      }
    }
  }
}
```

Leave `BOTLOCK_MASTER_KEY` out of config files you commit. See "Vault key" below for where the key is kept.

Restart Claude Code. Ask: “Call `botlock_status` and summarize findings.”

Then, in this order:

1. `botlock_identity_create` with a label like `prod-writer`
2. `botlock_policy_show` to see the built-in deny-by-default policy, edit it, then `botlock_policy_load` with your version (JSON, `version: 1`). The Field Kit YAML templates are a good starting point for the values.
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

## Vault key

The vault master key is **never written into `state.json`**. Bot Lock looks for it in this order:

1. `BOTLOCK_MASTER_KEY` environment variable (best: inject it from your secret manager).
2. The OS keychain, when one is available: macOS Keychain (`security`) or the Linux Secret Service (`secret-tool`, needs a desktop session / D-Bus). Set `BOTLOCK_KEYCHAIN=0` to skip it.
3. A separate key file with mode `0600`: `$BOTLOCK_HOME/master.key`, or the path in `BOTLOCK_KEY_FILE`.

With the key file fallback, Bot Lock prints a warning to stderr and `botlock_status` lists a finding: anyone who can read both the key file and `state.json` can decrypt your secrets. Put `BOTLOCK_KEY_FILE` on a different disk or use option 1 or 2 for real separation. Back the key up. If it is lost, stored secrets cannot be recovered, and Bot Lock will not silently mint a new key while sealed secrets exist.

Upgrading from 1.0.0: the first run moves the old `masterKey` out of `state.json` into the keychain or key file and rewrites `state.json` without it. If `BOTLOCK_MASTER_KEY` is set to a different key, Bot Lock stops with an error instead of guessing.

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

## 7. Upgrade (optional, paid)

Everything above is free. The paid tiers are documentation and templates, not extra MCP tools:

- **Field Kit, $49 one-time:** the full Bot Lock Playbook (threat model, weighted control catalog, policy how-to, kill-switch runbook, verification drills V1–V10, 30-day adoption plan) and the policy YAML templates (deny-by-default tools, MCP allowlist, secrets, kill switch).
- **Pro, $149 one-time:** everything in the Field Kit. Today Pro contains the same playbook and templates; it is the tier for teams that want to pay more to back the free MCP server.

Checkout: https://bot-lock.netlify.app/#pricing
