# Bot Lock MCP server

Local control plane for AI agents. **Bot Lock** by AgentHive Inc. gives a tool-using agent an identity, an encrypted vault, a hash-chained audit log, and policy gates — over MCP.

This is defense in depth. It reduces the chance of a rogue or injected agent acting with your full credentials. It does **not** make compromise impossible. A process with host access can still bypass a userspace gate.

## What it does

| Tool | Purpose |
| --- | --- |
| `botlock_status` | Identity, vault, audit validity, policy, kill switch, findings |
| `botlock_identity_create` / `_show` | Ed25519 agent identity (public key only on show) |
| `botlock_vault_put` / `_get` / `_list` | AES-256-GCM secrets; values never written into audit payloads |
| `botlock_audit_append` / `_tail` / `_verify` | Signed, hash-chained log |
| `botlock_scope_check` | Allow / deny / confirm before a tool runs |
| `botlock_policy_show` / `_load` / `_reset` | Deny-by-default policy document |
| `botlock_kill_switch` | Halt every subsequent scope check |

State lives in `$BOTLOCK_HOME/state.json` (default `~/.botlock/state.json`), mode `0600`. Set `BOTLOCK_MASTER_KEY` to pin the vault key across machines.

## Install

```bash
cd mcp
npm install
npm test
npm run build
```

See [INSTALL.md](./INSTALL.md) for Claude Code and Cursor.

## Honesty

- Scope checks only work if the **host agent consults them** before calling other tools.
- The vault protects secrets at rest on this disk. It is not an HSM.
- Hash-chained audit detects tampering of the local file. It is not a remote SIEM.
- Use with the Field Kit policies and the kill-switch runbook. Software alone is not a program.