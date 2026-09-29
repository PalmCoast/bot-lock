# Bot Lock MCP server

Free, MIT-licensed local control plane for AI agents. **Bot Lock** by AgentHive Inc. gives a tool-using agent an identity, an encrypted vault, a hash-chained audit log, and policy gates — over MCP.

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

State lives in `$BOTLOCK_HOME/state.json` (default `~/.botlock/state.json`), mode `0600`. The vault master key is **not** stored there. It comes from `BOTLOCK_MASTER_KEY`, else the OS keychain (macOS Keychain or Linux Secret Service), else a separate `0600` key file (`$BOTLOCK_HOME/master.key` or `BOTLOCK_KEY_FILE`) with a warning. See [INSTALL.md](./INSTALL.md#vault-key).

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
- The vault encrypts secrets at rest. With the key-file fallback, someone who can read both the key file and `state.json` can decrypt them; use `BOTLOCK_MASTER_KEY` or the OS keychain for real separation. It is not an HSM.
- Hash-chained audit detects tampering of the local file. It is not a remote SIEM.
- Use with the Field Kit policies and the kill-switch runbook. Software alone is not a program.

## Free vs paid

This MCP server is free (MIT). The optional paid tiers at https://bot-lock.netlify.app/#pricing are the playbook and templates:

- **Field Kit ($49 one-time):** the Bot Lock Playbook and the policy YAML templates.
- **Pro ($149 one-time):** everything in the Field Kit. It currently has no Pro-only files; it is the higher tier for teams that want to back the free server.
