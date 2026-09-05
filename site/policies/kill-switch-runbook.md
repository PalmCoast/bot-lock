# Bot Lock — Kill-Switch Runbook

**AgentHive Inc.** · Companion to `kill-switch.yaml` and Field Kit Playbook §6  
**Mode:** fail closed · **Product:** Bot Lock

> Engage to halt agent tool use under uncertain or hostile influence. Restore only with human security approval, incident ticket, and root-cause note. Defense only — no exploit procedures.

## 1. Purpose

Assume prompt injection or tool misuse may land. The kill switch breaks the kill chain: freeze tools, revoke session tokens, cut egress, snapshot audit, notify on-call, quarantine runtime, and require human reauth to resume.

## 2. Who can engage / restore

| Role | Engage | Restore |
|------|--------|---------|
| Security on-call | Yes | Yes (with ticket + root cause) |
| Agent owner | Yes (own agents) | Prefer no — route to security |
| Platform on-call | Yes | With security |
| Automated triggers | Yes | No |
| The agent | No | No |

Break-glass contacts must live outside the agent vault.

## 3. Triggers (`kill-switch.yaml`)

- `anomalous_tool_burst` — high tool_calls_per_minute OR tool outside allowlist  
- `exfil_pattern` — bulk_read + external_egress same session  
- `injection_detector_high` — gateway high score OR policy deny storm  
- `hash_mismatch_mcp` — MCP hash ≠ pinned  
- `human_panic` — operator engages  
- `spend_cap` — session/daily spend ≥ cap  
- `privilege_escalation_attempt` — denied tool class OR audience mismatch  

## 4. Halt path (ordered)

1. `freeze_new_tool_calls`  
2. `revoke_session_tokens`  
3. `cut_network_egress`  
4. `snapshot_audit_trail`  
5. `notify_oncall`  
6. `quarantine_agent_runtime`  
7. `require_human_reauth_to_resume` (default: remain quarantined)

Do not skip revoke or snapshot because of suspected false positives.

## 5. Operator checklist

1. Confirm `agent_id` and `env`.  
2. Engage `human_panic` if automation did not fire.  
3. Verify freeze + revoke + egress cut.  
4. Open incident ticket; preserve logs (no “cleanup” before snapshot).  
5. Notify agent owner and business owner.  
6. Investigate with audit (`session_id`, `policy_version`, tool decisions).  
7. Remediate (policy rollback, MCP remove, secret rotate).  
8. Restore only when resume gates pass.

## 6. Resume gates

All required:

- Approver role: `security_oncall` (or documented equivalent)  
- `incident_ticket_id`  
- `root_cause_note`  
- Tokens rotated if revoke fired  
- `policy_version` pinned / rolled back as needed  

## 7. Caps (template defaults — tune per env)

- `daily_spend_usd`: 50  
- `session_spend_usd`: 10  
- `max_egress_bytes_per_session`: 5_000_000  
- `max_external_recipients`: 0 until HITL raises  

## 8. Drill cadence

- Day-0: `human_panic` in staging  
- Monthly: rotate authorized synthetic trigger drills  
- After major policy change: halt + restore once  
- Record MTTA / MTTR; restore must not outrun verification  

## 9. User-facing behavior

Return a degraded availability message without leaking internal trigger detail useful for attacker iteration. Pause HITL queues for the quarantined agent. Sibling agents must not inherit its tokens.

## 10. Related files

- `/workspace/botlock/policies/kill-switch.yaml`  
- `/workspace/botlock/playbook/BOT-LOCK-PLAYBOOK.md` §6  
- Audit event shapes: playbook §10 (`kill_switch.engaged` / `kill_switch.restore`)  

---

*Bot Lock Field Kit — AgentHive Inc. — Defense only.*
