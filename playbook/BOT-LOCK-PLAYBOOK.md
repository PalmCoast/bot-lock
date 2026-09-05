# Bot Lock Field Kit Playbook

**AgentHive Inc.** — Operator-dense, defense-only guidance for securing AI agents that use tools, MCP servers, and credentials.  
**Product:** Bot Lock · **Companion:** Field Kit ($49 one-time) · **Version:** 2.1  
**Audience:** Platform engineers, security operators, SRE/on-call, and agent owners who run production or staging agent systems they are authorized to control.

> This playbook designs, reviews, and verifies agent control planes. It does **not** provide exploit PoCs, attack payloads, bypass recipes, or unauthorized testing procedures. Authorized self-assessment themes align with Bot Lock Check. Red-team exploit reproduction is out of scope.

---

## Table of contents

1. [Why this exists](#1-why-this-exists)
2. [Core principles](#2-core-principles-highest-weight-first)
3. [Threat model checklist](#3-threat-model-checklist)
4. [Weighted control catalog](#4-weighted-control-catalog-defense-in-depth)
5. [Policy how-to (Field Kit YAML)](#5-policy-how-to-field-kit-yaml-templates) — includes OAuth/token and exfil/I/O how-tos
6. [Kill-switch runbook](#6-kill-switch-runbook)
7. [Authorized verification playbook](#7-authorized-verification-playbook) — includes drills V1–V10
8. [Anti-patterns](#8-anti-patterns)
9. [30-day adoption / rollout plan](#9-30-day-adoption--rollout-plan)
10. [Sample audit event shapes](#10-sample-audit-event-shapes)
11. [Incident vignettes](#11-incident-vignettes)
12. [Honest limits](#12-honest-limits)
13. [Product map and file map](#13-product-map-and-file-map)
14. [Appendices](#appendix-a--glossary-short) — glossary, operator card, implementation notes, tabletops, Check mapping, FAQ, **weekly audit ritual**, **on-call card**, **procurement / honesty FAQ**

---

## 1. Why this exists

AI agents that read untrusted content and call tools turn **text into actions**. That is the product value and the security problem in the same sentence. A support agent that can open tickets, draft replies, and look up customer records is useful until a poisoned email, a malicious PDF comment, or a compromised MCP plugin rewrites its intent and those same tools become the blast radius.

Operators are already shipping agents with:

- **Tool access** — email, calendars, browsers, shells, databases, ticketing, CI/CD, payment APIs, cloud control planes.
- **MCP and plugin ecosystems** — third-party servers that extend capability without going through traditional app-sec review gates.
- **Credentials and non-human identities (NHI)** — service accounts, OAuth tokens, API keys, and delegated user scopes that persist longer than any single chat turn.
- **Multi-hop context** — RAG corpora, long-term memory, agent-to-agent messages, and shared session state where untrusted text can persist.

Industry educational sources (weighted themes from English operator-facing material, Mar–Sep 2026) repeatedly surface the same failure modes. Bot Lock Check and this Field Kit playbook weight controls by how often those themes appear in that research set:

| Weight | Theme | Operator focus |
|--------|-------|----------------|
| 16/20 | Prompt injection / jailbreak | Untrusted text as executable influence |
| 16/20 | Logging / monitoring / audit | Assume breach; instrument everything |
| 12/20 | Least privilege / IAM | Task-scoped, time-bound access |
| 11/20 | Excessive agency | Cap autonomy and blast radius |
| 11/20 | Agent tool abuse | Tools are the new attack surface |
| 11/20 | Supply chain / MCP / plugins | Untrusted by default |
| 10/20 | Secrets management | Vaults, not prompts |
| 9/20 | Data exfiltration | DLP + egress controls |
| 9/20 | Guardrails / I/O filtering | Defense outside the model |
| 9/20 | Token delegation / OAuth | No confused-deputy passthrough |

### Who this playbook is for

- **Agent owners** who decide which tools and credentials an agent may use for a business workflow.
- **Platform / runtime operators** who load policy YAML, wire audit sinks, and run kill-switch drills.
- **Security engineers** who threat-model entrances, review allowlists, and score posture with Bot Lock Check.
- **On-call responders** who need a halt path that fails closed without improvising under pressure.

### What “operator-dense” means here

This is not a marketing brochure and not a theoretical paper. It is a working companion to the Field Kit policy templates in `/workspace/botlock/policies/`. Every major section should leave you able to: inventory something, decide a default, load or change a policy, verify a control on systems you own, or restore after a halt. Where we cannot give a universal knob (every org’s IdP and gateway differ), we give the decision criteria and the audit evidence you should expect.

### What this product is

**Bot Lock** by AgentHive Inc. is an AI agent security control plane mindset and Field Kit: identity discipline, vault-oriented secrets, audit trails, deny-by-default tools, and playbook-backed operations. Pricing context for this document:

| Tier | Price | Role |
|------|-------|------|
| Bot Lock Check | Free | Weighted self-assessment UX |
| Field Kit | $49 one-time | This playbook + policy YAML starters |
| Pro | $149 | Field Kit plus deeper MCP identity / vault / audit guidance path |

Brand is **Bot Lock** only. No monthly subscription framing appears in this Field Kit companion.

### The operator problem in one paragraph

Model instructions are soft. Tool APIs are hard. If you only strengthen the soft layer (“ignore malicious instructions”), a successful injection still reaches hard capabilities. Bot Lock’s bias is the opposite: treat injection as likely, put policy and identity outside the model, deny tools by default, short-live credentials, log everything that matters, and keep a kill switch that humans can engage without debating philosophy at 02:00.

---

## 2. Core principles (highest weight first)

Ranked by research weight. When two controls conflict under time pressure, prefer the higher-ranked principle unless a documented exception exists.

### 2.1 Treat untrusted text as executable influence

Prompts, documents, email bodies, calendar invites, web pages, code comments, issue trackers, OCR output, RAG chunks, and **tool return payloads** can overwrite agent intent. Direct prompt injection (user says “ignore previous instructions”) and indirect prompt injection (content the agent fetches later contains instructions) are first-class threats, not edge cases.

**Operator implication:** Mark every content channel as trusted or untrusted. Untrusted content may be *summarized* under policy; it must not silently expand tool authority. Delimit untrusted content in orchestration; never merge it into system policy text.

### 2.2 Assume breach; instrument everything

Filters rot. Novel phrasing appears. Prefer detection and response over hoping the model always refuses. Log prompts (with redaction), tool calls, identity/token issuance and use, policy decisions, and outcomes. Retain enough to reconstruct a session after an incident.

**Operator implication:** If you cannot answer “which agent, which tool, which credential, which egress host, in which order?” you do not have an agent audit trail—you have chat history.

### 2.3 Least privilege for agents and tools

Task-scoped, time-bound permissions beat god-mode service accounts. An agent that needs to read one ticket queue does not need org-wide mailbox admin. Over-permissioned agents convert a single injection into multi-system damage.

**Operator implication:** Separate NHIs per agent (or per agent class). Prefer short TTL tokens issued at tool-call time. Review allowlists when workflows change, not only when incidents happen.

### 2.4 Bound agency; capability is not authorization

Autonomous tool chaining amplifies a single bad turn into bulk reads, sends, deletes, deploys, or spends. Cap goals, tools, loop iterations, concurrent sessions, and blast radius. A model “wanting” to help is not authorization to act.

**Operator implication:** Encode max autonomy levels in policy. Require human-in-the-loop (HITL) for high-impact action classes even if the tool is later allowlisted.

### 2.5 Tools are the attack surface

Every tool—email, browser, shell, DB, ticketing, payment, MCP—extends blast radius. Validate arguments against schemas. Allowlist tools per agent. Gate dangerous actions. Never concatenate model text into SQL, shell, HTML sinks, or unrestricted code interpreters.

**Operator implication:** Maintain a tool inventory with blast-radius ratings. Deny-by-default is the Field Kit baseline (`deny-by-default-tools.yaml`).

### 2.6 Supply chain and plugins are untrusted by default

Third-party MCP servers, skills, and plugins can ship malicious instructions, over-broad credential requests, or silent updates. Verify provenance. Pin versions and hashes. Isolate per server. Do not install arbitrary community skills on hosts that hold production credentials.

**Operator implication:** `mcp-allowlist.yaml` starts at install/connect deny. Unlisted equals denied.

### 2.7 Secrets never ride in prompts or agent memory casually

API keys, tokens, and passwords belong in vaults and short-lived issuance—not system prompts, chat transcripts, RAG corpora, or shared multi-agent memory.

**Operator implication:** Scan and scrub. Issue credentials at the broker/tool boundary. Revoke on halt.

### 2.8 Prevent exfiltration as a primary outcome

A common kill-chain end state after injection is bulk read plus external egress (email, webhook, public paste, cloud object write). Apply DLP on outputs and egress allowlists on tools and networks.

**Operator implication:** Pair bulk-read detectors with egress caps. Prefer zero external recipients until HITL raises the ceiling.

### 2.9 Defense outside the model

AI gateways, policy engines, and I/O filters inspect traffic before and after the model. Model-only “please don’t” instructions are insufficient against determined or obfuscated influence.

**Operator implication:** Policy decisions must be enforceable in the runtime/orchestration layer even when the model complies with attacker intent.

### 2.10 Separate identity, delegation, and trust hops

OAuth token exchange, agent-to-agent delegation, and NHI vs human identity need explicit audiences and path-aware authorization. Token passthrough creates confused-deputy failures: Agent B acts with Agent A’s token for a purpose A never authorized.

**Operator implication:** Bind audience. Re-authorize at each hop. Log issuance and denial.

---

## 3. Threat model checklist

Walk this checklist for every LLM or agent feature before production and after material changes (new tool, new MCP server, new data connector, new autonomy level). Mark assets, entrances, and blast radius explicitly. Store the result with the agent’s runbook.

### 3.1 Assets

- [ ] System prompts / proprietary instructions and policy text
- [ ] User and enterprise data (PII, customer content, regulated records)
- [ ] Tool credentials, OAuth tokens, API keys, NHIs
- [ ] Downstream systems reachable by tools (email, cloud APIs, DBs, CI/CD, browsers, payment rails)
- [ ] Model / RAG corpora and long-term agent memory
- [ ] Audit logs themselves (integrity and retention)
- [ ] Spend / quota budgets tied to model and tool usage

For each asset, note: **owner**, **sensitivity**, **where it appears in context**, and **which tools can touch it**.

### 3.2 Entrances (untrusted input)

- [ ] Direct user chat / API messages
- [ ] Indirect content: docs, email, calendar, tickets, web, PDFs, images/OCR, repo comments, wiki pages
- [ ] Retrieved RAG chunks and tool-returned text (including error messages)
- [ ] Third-party MCP servers, plugins, skills, and model updates
- [ ] Multi-agent messages and shared context / token passthrough
- [ ] Operator-uploaded “few-shot” examples that may contain live secrets
- [ ] Scheduled triggers that pull external content without a human reading it first

Treat every entrance as a potential instruction channel unless you have a hard boundary that strips or isolates influence.

### 3.3 Attacker goals (themes — defensive framing)

Frame these as **outcomes you must reduce**, not recipes:

- [ ] Intent hijack via prompt injection / jailbreak themes
- [ ] Sensitive disclosure / system-prompt or secret leakage
- [ ] Tool abuse / excessive agency (send, spend, delete, deploy, grant)
- [ ] Data exfiltration via connectors or covert channels
- [ ] Insecure output handling (model text reaching SQL/shell/HTML sinks)
- [ ] Memory / RAG poisoning for persistence across sessions
- [ ] Credential theft / privilege escalation via delegation mistakes
- [ ] Resource abuse / cost runaway
- [ ] Supply-chain compromise of tools / MCP
- [ ] Audit blinding (logging disabled, redaction abused to hide actions)

### 3.4 Trust boundaries to draw

- [ ] User ↔ orchestration ↔ model
- [ ] Model ↔ tools / MCP
- [ ] Agent ↔ agent (multi-agent)
- [ ] Enterprise human identity ↔ non-human / agent identity
- [ ] Sandbox / network egress ↔ internal resources
- [ ] Dev / staging agents ↔ production data planes
- [ ] Policy change control ↔ runtime enforcement

Document who may cross each boundary and what evidence is logged when they do.

### 3.5 Quick blast-radius scoring (operator heuristic)

For each tool on an agent, score **Impact × Likelihood of misuse if intent is hijacked**:

| Score | Meaning | Example posture |
|-------|---------|-----------------|
| 1 | Read-only, internal, low-sensitivity | Search public docs |
| 2 | Read sensitive internal | Read ticket with PII |
| 3 | Write limited / reversible | Draft (not send) email |
| 4 | Irreversible or external | Send email, deploy, pay |
| 5 | Admin / shell / wildcard cloud | Unrestricted shell, org admin API |

Anything scored 4–5 needs HITL, narrow identity, and kill-switch coverage before production.

---

## 4. Weighted control catalog (defense in depth)

Combine controls. No single filter is enough. Subsections follow research weight and operator workflow. Each control lists **intent**, **how to implement with Field Kit bias**, and **evidence** you should see in audit.

### 4.1 Prompt injection and content defenses

**Intent:** Reduce the chance that untrusted text silently becomes policy; ensure that even when influence lands, actions stay gated.

**Controls:**

1. **Instruction hierarchy in orchestration** — System/policy text is not overwritten by user or retrieved content. Keep untrusted content in clearly delimited channels (e.g., “document body” fields) that tools and planners treat as data.
2. **AI gateway / input inspection** — Inspect inbound user and retrieved content for known injection patterns and obfuscation themes. Use as a signal, not as the only gate. High scores should raise friction (HITL, reduced tools), not only log.
3. **Output filtering and action gating** — Inspect model proposals before tool execution. The runtime decides allow/deny; the model does not self-authorize.
4. **Dual-role patterns (planner vs executor)** — Planner reasons over untrusted text; executor only runs allowlisted tools with schema-validated args. Planner never receives raw credentials.
5. **Content trust labels** — Tag sources (user, email, web, RAG, tool). Policy can forbid high-impact tools when the last N turns include untrusted labels.
6. **Assume initial influence; break the kill chain** — Design for “injection may land.” Break subsequent links: tool allowlist, arg validation, egress, secrets, HITL, kill switch.

**Evidence:** Policy deny events when untrusted content would expand tool set; gateway scores attached to session IDs; no system-prompt text in user-visible logs.

### 4.2 Identity, authorization, and agency

**Intent:** Make every action attributable to an agent NHI with scoped rights; prevent “helpful” overreach.

**Controls:**

1. **Separate agent NHI from human identity** — Humans authenticate to approve; agents act as NHIs. Mixing them breaks revocation and audit.
2. **Task-scoped, time-bound credentials** — Prefer issuance at tool-call time with TTL (Field Kit secrets template defaults to short TTL).
3. **Autonomy levels** — Encode levels (e.g., 0 suggest-only, 1 read tools, 2 limited write, 3 unrestricted forbidden in prod) in `deny-by-default-tools.yaml`.
4. **HITL for high-impact classes** — send, pay, delete, deploy, grant_access, export_bulk_data, write_production.
5. **Session and loop caps** — `max_tool_calls_per_session`, `max_loop_iterations` to stop runaway agency.
6. **Path-/policy-aware authorization** — Token validity ≠ permission for this resource and this action.

**Evidence:** Issuance logs with audience and TTL; approval records for HITL; autonomy level in agent config snapshots.

### 4.3 Tool least privilege

**Intent:** Default deny; only enable tools required for the current workflow.

**Controls:**

1. **Deny-by-default allowlist** — Explicit `tools.allow`; everything else denied.
2. **Args schemas and constraints** — Types, patterns, max limits, destination constraints (e.g., internal_docs_only).
3. **Hard denials for high-blast classes** — Unrestricted shell, unrestricted browser, db_admin unless a separate hardened runbook exists.
4. **Never pass model text to dangerous interpreters** — Reject sql_concat, shell_concat, unsanitized_html; never pass model text to shell, sql_execute, eval, unrestricted code_interpreter.
5. **Per-environment allowlists** — Staging may allow more for testing; production stays tight. Do not copy staging allowlists wholesale.

**Evidence:** Every tool call logged with allow/deny decision; denied attempts visible without enabling the tool.

### 4.4 MCP / plugin supply chain

**Intent:** Treat MCP servers like untrusted software supply chain until proven otherwise.

**Controls:**

1. **Install/connect deny by default** — `mcp-allowlist.yaml` mode `allowlist_only`.
2. **Pin version + hash** — Require pinned version and `hash_sha256`; kill on mismatch.
3. **Declare network and credential scope** — No wildcards; no “needs shell/full filesystem” on sensitive hosts.
4. **Isolate per server** — Separate credentials per server; no credential passthrough between servers.
5. **Owner attestation / change control** — New MCP entries require owner + security review, same as adding a production dependency.
6. **Runtime reconnect checks** — Re-verify hash on connect; alert on drift.

**Evidence:** Install/connect/deny logs; hash mismatch triggers kill-switch path; allowlist diff in change tickets.

### 4.5 Secrets management

**Intent:** Credentials never become prompt or memory residents.

**Controls:**

1. **Vault-only mode** — Issue from vault/broker at tool-call time (`secrets.yaml`).
2. **No secrets in prompts / memory / RAG** — Enforce with redaction patterns and blocked exports.
3. **Short-lived tokens** — Default max TTL (template: 900 seconds) unless a documented exception exists.
4. **Audience binding** — No bearer passthrough across agents.
5. **Separate NHIs; forbid shared god accounts** — One shared admin bot account is an anti-pattern.
6. **Redaction on detect** — block_log_export, alert, scrub_context.

**Evidence:** Issuance and revocation logs; denied secret access events; scrub events when patterns hit context.

### 4.6 Data exfiltration and I/O guardrails

**Intent:** Make bulk read + external send hard without human approval.

**Controls:**

1. **Egress allowlist** — Network allowlist_only; block private ranges and cloud metadata endpoints by default.
2. **DLP on outputs** — Detect sensitive patterns before external tools fire.
3. **Bulk export as HITL class** — `export_bulk_data` requires approval.
4. **Recipient caps** — `max_external_recipients: 0` until HITL raises.
5. **Session egress byte caps** — Kill-switch template includes `max_egress_bytes_per_session`.
6. **Tool pairing detectors** — Bulk internal read followed by external egress in one session is a kill-switch trigger theme.

**Evidence:** Egress deny logs; DLP hits; paired-pattern alerts; HITL tickets for exports.

### 4.7 Token delegation and OAuth

**Intent:** Prevent confused-deputy and silent privilege expansion across hops.

**Controls:**

1. **Explicit audience on every token** — Tokens for service A are rejected by service B.
2. **Re-authorization on agent-to-agent handoff** — Do not pass bearer tokens in shared context.
3. **Narrow OAuth scopes** — Prefer read-only scopes; expand only with change control.
4. **Revocation on halt** — Kill-switch revokes session tokens before restore debate.
5. **Human approval for grant_access tools** — Agents must not mint broad grants autonomously.

**Evidence:** Audience mismatch denials; handoff events without raw token material; revocation timestamps tied to incident IDs.

### 4.8 Audit and monitoring

**Intent:** Reconstruct sessions; detect anomalies; feed kill-switch and postmortems.

**Controls:**

1. **Log every tool call** — Args redacted; outcome included; immutable sink preferred.
2. **Log policy decisions** — Allow, deny, HITL pending, kill engaged.
3. **Log identity events** — Issuance, use, revocation, audience mismatch.
4. **Log MCP install/connect/invoke** — Supply-chain forensics.
5. **Retain long enough** — Kill-switch template suggests 365 days for halt events; align with your compliance floor.
6. **Alert on deny storms and spend caps** — Operational signal, not vanity metrics.
7. **Protect log integrity** — Agents should not be able to delete their own audit trail.

**Evidence:** Sample shapes in §10; SIEM rules mapped to trigger IDs in `kill-switch.yaml`.

### 4.9 Isolation

**Intent:** Contain compromise of runtime, MCP server, or tool to a small blast radius.

**Controls:**

1. **Ephemeral / sandboxed runtimes** — Prefer short-lived compute per session for high-risk agents.
2. **Network isolation** — Egress allowlists; no lateral movement to admin networks.
3. **Per-MCP isolation** — Separate process/container identity where platform allows.
4. **Separate staging data** — Never point experimental agents with loose tools at production data stores.
5. **Quarantine on halt** — Runtime freeze + egress cut as ordered actions.

**Evidence:** Quarantine events; network deny logs; environment tags on every audit event (`env: staging|prod`).

---


### 4.10 Layering order under time pressure

When you cannot implement everything at once, add layers in this order for a tool-enabled agent already exposed to untrusted content:

1. Audit on (without audit you cannot operate).  
2. Deny-by-default tools + HITL for impact ≥ 4.  
3. Kill switch wired and drilled.  
4. Secrets out of prompts; short TTL.  
5. Egress allowlist + metadata blocks.  
6. MCP allowlist with pins/hashes.  
7. Stronger content labeling / gateway friction.  
8. Isolation hardening and multi-agent boundary review.

This order privileges **visibility and halt**, then **capability reduction**, then **supply chain and isolation**. It matches the research weight on audit and injection while acknowledging that tools and credentials are where damage becomes real.


## 5. Policy how-to (Field Kit YAML templates)

Field Kit ships starter policies under `/workspace/botlock/policies/` (and mirrored under the site package). They are **templates**: adapt hosts, hashes, spend caps, and allowlists to your environment before production.

| File | Policy ID | Mode | Purpose |
|------|-----------|------|---------|
| `deny-by-default-tools.yaml` | `botlock.tools.deny_by_default` | `deny_by_default` | Tool allowlist, HITL classes, arg validation, egress, audit |
| `secrets.yaml` | `botlock.secrets` | `vault_only` | No secrets in prompts/memory; short TTL; audience binding; redaction |
| `mcp-allowlist.yaml` | `botlock.mcp.allowlist` | `allowlist_only` | Pin MCP servers; isolate; kill on hash mismatch |
| `kill-switch.yaml` | `botlock.kill_switch` | `fail_closed` | Triggers, ordered halt actions, caps, resume gates |

### 5.1 Day-0 load (first install)

**Goal:** Land in a safe default: agents can do almost nothing until you explicitly open scope.

1. **Inventory** — List agents, tools, MCP servers, credentials, egress needs, and owners. Store inventory next to policies.
2. **Copy templates** into your policy repo or control-plane config store. Do not edit only a local laptop copy if production loads from git.
3. **Fill placeholders** — `${AGENT_NHI_ID}`, `${ORG}`, `REPLACE_WITH_PINNED_HASH`, `allowed_hosts`, spend caps.
4. **Start closed** — Keep `tools.allow` minimal (e.g., search_docs / read_ticket / summarize). Leave shell, unrestricted browser, and db_admin denied.
5. **Wire audit sink** — Confirm events reach an immutable or append-preferred store before enabling any write tools.
6. **Wire kill-switch actions** — Map `actions_ordered` to real runtime APIs (freeze tools, revoke tokens, cut egress, snapshot, notify, quarantine). A YAML file that nobody’s runtime reads is documentation, not a control.
7. **Dry-run mode if available** — If your control plane supports shadow deny (log would-deny without enforcing), run 24–72 hours, then enforce.
8. **Record baseline Bot Lock Check score** — Free Check gives a weighted self-assessment snapshot for later deltas.

**Day-0 acceptance criteria:**

- Unknown tools deny with an audit event.
- Unknown MCP connect denies.
- Secret-like strings in prompts trigger scrub/alert paths in staging.
- Manual human_panic kill switch freezes new tool calls in a drill.

### 5.2 Day-2 operations (steady state)

**Daily / continuous:**

- Watch deny storms, HITL queue depth, spend vs caps, MCP connect failures, hash mismatch alerts.
- Triage false positives carefully: loosening policy is a change-controlled act, not a chat reply to the agent.

**When adding a tool:**

1. Write blast-radius score (§3.5).
2. Add to `tools.allow` with args schema and constraints.
3. If impact ≥ 4, keep in `require_human_approval` or equivalent.
4. Update egress hosts if needed.
5. Add audit dashboard panel for the new tool ID.
6. Re-score Bot Lock Check themes for tool abuse / least privilege.

**When adding an MCP server:**

1. Obtain pinned version + hash from a trusted build pipeline.
2. Declare network + credential scopes; reject wildcards.
3. Isolate credentials; never share the prod vault role with an experimental MCP.
4. Enable `kill_switch_on_hash_mismatch`.
5. Change ticket with owner attestation.

**When rotating secrets:**

- Prefer vault rotation jobs; confirm agents never logged raw values.
- Revoke old TTL families; watch denial spikes for missed re-issue wiring.

### 5.3 Change control

Treat policy like production firewall rules:

| Change type | Minimum gate |
|-------------|--------------|
| Add read-only internal tool | Owner review + audit check |
| Add write / send / deploy tool | Security review + HITL + kill-switch drill for that class |
| Add MCP server | Owner attestation + hash pin + isolation review |
| Raise spend / egress caps | Security + finance/ops as applicable |
| Disable a kill-switch trigger | Explicit exception with expiry; never silent |
| Expand OAuth scopes | Identity review + audience re-bind |

**Required change record fields:** requester, agent IDs affected, policy diff, blast-radius note, rollback plan, evidence of audit still green.

**Rollback:** Keep previous policy version immutable. Runtime should be able to pin `policy_version`. On incident, roll back first; debate later.

### 5.4 Mapping YAML knobs to principles

- `mode: deny_by_default` → principles 2.3, 2.5  
- `max_autonomy_level` / loop caps → 2.4  
- `require_human_approval` → 2.4, 2.8  
- `argument_validation.never_pass_model_text_to` → 2.5, 2.9  
- `egress.allowlist_only` + metadata blocks → 2.8, 2.9  
- `vault_only` / `max_ttl_seconds` / `audience_binding` → 2.7, 2.10  
- `mcp` pin + isolate + hash kill → 2.6  
- `kill_switch` fail_closed → 2.2, 2.4  

### 5.5 Environment promotion

Promote policies **staging → prod** with the same discipline as app deploys:

1. Staging enforce for N days with production-like untrusted inputs (authorized test corpus).
2. Diff allowlists; remove staging-only debug tools.
3. Confirm prod NHIs and hashes (never reuse staging tokens).
4. Run kill-switch drill in prod-equivalent runtime or carefully scoped prod drill window.
5. Tag release with `policy_version` and Bot Lock Check score snapshot.

### 5.6 OAuth / token delegation how-to (maps to `secrets.yaml`)

Token mishandling turns a helpful multi-agent workflow into a confused-deputy incident. Field Kit’s `secrets.yaml` encodes the non-negotiables; this subsection is the operator how-to for wiring them.

**Primary YAML knobs (`policies/secrets.yaml`):**

| Knob | Template value | Operator action |
|------|----------------|-----------------|
| `mode` | `vault_only` | Credentials issued at tool-call time from vault/broker—not preloaded into prompts or shared memory |
| `rules.short_lived_tokens.max_ttl_seconds` | `900` | Prefer ≤15 minutes unless a documented exception ticket exists |
| `rules.audience_binding` | `enforce: true` | Every token has an explicit audience; service B rejects tokens minted for service A |
| `rules.separate_nhi` | `enforce: true` | Agent NHI ≠ human identity; one NHI per agent (or tight agent class) |
| `rules.no_secrets_in_prompts` / `no_secrets_in_memory` | `enforce: true` | Scan prompts, few-shots, RAG, and long-term memory for secret shapes |
| `forbidden.token_passthrough_multi_agent` | listed | Handoffs pass references (ticket IDs, doc IDs), never raw bearer material |
| `redaction.on_detect` | `block_log_export`, `alert`, `scrub_context` | Synthetic secret-shaped strings in staging must fire these paths |
| `audit.log_issuance` / `log_revocation` / `log_denied_secret_access` | `true` | Joinable to `session_id` and `agent_id` |

**Day-0 wiring checklist (OAuth / delegation):**

1. **Inventory every OAuth client** used by agents: client ID, allowed scopes, redirect/audience, owning team, refresh-token policy.
2. **Split clients per agent class** where the IdP allows—support-triage should not share the same broad client as deploy-bot.
3. **Scope floor:** start read-only (`read_tickets`, `read_docs`). Write scopes (`send`, `modify`, `admin`) require change control and HITL on the corresponding tools in `deny-by-default-tools.yaml`.
4. **Audience bind at issuance:** vault/broker stamps `aud` (or equivalent) for the exact API host the tool will call. Runtime rejects mismatched audience before the HTTP call.
5. **No refresh tokens in agent context.** If refresh is required, the broker holds it; the agent receives only short-lived access tokens.
6. **Handoff protocol:** Agent A completes work → writes a structured task record (IDs + objective) → Agent B starts a new session, mints its own token with its own NHI and audience. Shared chat memory must not contain `Authorization` headers or token JSON.
7. **Revoke-on-halt:** map kill-switch action `revoke_session_tokens` to the broker’s revoke API for that session’s token family. Prove it in a staging drill.
8. **Denial visibility:** audience mismatch and denied secret access must produce audit events (see §10.4 style plus a deny twin). If denials are silent, you cannot operate.

**Steady-state operations:**

- Weekly: sample 10 issuance events; confirm TTL ≤ policy max and audience matches tool host.
- On scope expansion: identity review + playbook §5.3 change record + Bot Lock Check re-score on token-delegation theme.
- On multi-agent feature launch: tabletop Exercise-style review of handoff paths (Appendix D) before prod.
- On halt: confirm revocation timestamps precede any restore debate.

**Pass criteria for “delegation is wired”:** staging shows (a) audience mismatch deny + audit, (b) handoff logs without raw bearer material, (c) halt revokes tokens within your SLO (document it—e.g., &lt; 60s).

**Common failure modes (fix these, do not normalize them):**

- “Temporary” long-lived tokens left in env vars after a demo.
- One shared service account for all agents “until we have time.”
- Agent B reuses Agent A’s token because “the API already authorized us.”
- Logging full token responses “just in staging” that later becomes the prod log pipeline.

### 5.7 Exfiltration and I/O guardrails how-to (maps to tools + kill-switch YAML)

Exfiltration is a primary post-injection outcome: bulk internal read, then external send. Field Kit splits prevention across `deny-by-default-tools.yaml` (egress, HITL, arg validation) and `kill-switch.yaml` (pairing trigger, caps, ordered halt).

**Primary YAML knobs:**

| File | Knob | Operator intent |
|------|------|-----------------|
| `deny-by-default-tools.yaml` | `defaults.require_human_approval` includes `export_bulk_data`, `send_email`, `send_message` | High-impact egress classes wait for a human |
| `deny-by-default-tools.yaml` | `egress.network: allowlist_only` | Unlisted hosts deny |
| `deny-by-default-tools.yaml` | `egress.allowed_hosts: []` | Fill per env; empty means no tool egress until you open deliberately |
| `deny-by-default-tools.yaml` | `egress.block_private_ranges` / `block_metadata_endpoints` | SSRF / metadata theft themes blocked by default |
| `deny-by-default-tools.yaml` | `argument_validation.never_pass_model_text_to` | Model text never becomes shell/SQL/eval input |
| `deny-by-default-tools.yaml` | `audit.log_every_tool_call` | Reconstruct read→egress sequences |
| `kill-switch.yaml` | `triggers.exfil_pattern` | `bulk_read + external_egress` same session → halt |
| `kill-switch.yaml` | `caps.max_egress_bytes_per_session` | Template `5000000` — tune with evidence |
| `kill-switch.yaml` | `caps.max_external_recipients: 0` | No external recipients until HITL raises |
| `kill-switch.yaml` | `actions_ordered` includes `cut_network_egress` | Halt is not “log only” |

**Day-0 wiring checklist (exfil / I/O):**

1. **Classify tools** as internal-read, internal-write, external-egress, or admin. Only the first may start without HITL on most support/research agents.
2. **Fill `allowed_hosts`** from workflow reality (ticket API, docs host, model endpoint)—not from agent chat requests. Use deny logs as the candidate list (§C.3).
3. **Separate model-provider egress from tool egress** in the network policy so a document connector cannot open arbitrary destinations.
4. **Enable DLP-style output checks** before external tools fire (even a simple pattern layer for known regulated markers in your org). Hits should set decision `deny` or `pending_human_approval`, never silent allow.
5. **Define bulk_read** operationally for your detectors (e.g., N sensitive records or M bytes from internal tools in one session). Document the threshold next to `exfil_pattern`.
6. **Wire pairing alerts** into the same path as kill-switch automation—or accept that humans must catch it from dashboards (weaker).
7. **Recipient caps:** keep `max_external_recipients: 0` until a named workflow + HITL path exists.
8. **Prove cut_network_egress** in staging: after halt, runtime cannot reach external hosts even if a tool call somehow remains queued.

**Steady-state operations:**

- Watch deny storms on egress hosts and DLP hits; treat sudden allowlist expansion requests as change-control items.
- After adding any send/export tool: re-run authorized verification V6 and V8 (§7.6).
- Tune byte caps with finance/security jointly—raising caps is a security decision, not only FinOps.
- On suspected exfil: halt first (`human_panic` if automation quiet), then investigate with session reconstruction (§10). Do not “watch one more minute.”

**Pass criteria for “exfil controls are wired”:** staging shows (a) non-allowlisted host deny + audit, (b) metadata endpoint deny, (c) HITL pending for send/export fixtures you own, (d) synthetic bulk_read+egress pairing engages halt or at minimum pages with the correct trigger_id.

**I/O filtering note:** Input inspection (gateway scores, trust labels) and output gating are complementary. Labels on untrusted email/PDF/web content should raise friction on high-impact tools even when the model “sounds helpful.” Runtime policy wins over model compliance with attacker intent (principle 2.9).

---

## 6. Kill-switch runbook

Assume influence will sometimes land. The kill switch exists to **break the kill chain fast** and fail closed. This chapter matches `policies/kill-switch.yaml` and the companion runbook markdown if present.

### 6.1 Purpose and posture

- **Mode:** `fail_closed`
- **Bias:** Prefer temporary business interruption over unbounded tool use under uncertain intent.
- **Scope:** Per agent, per agent class, or fleet-wide—decide in advance and encode in runtime wiring.

### 6.2 Who can engage

Define roles before the first incident:

| Role | Can engage? | Can restore? | Notes |
|------|-------------|--------------|-------|
| Security on-call | Yes | Yes (with ticket) | Primary |
| Agent owner | Yes (own agents) | No (recommend) | Can halt; restore needs security |
| Platform on-call | Yes | With security | Runtime freeze / egress |
| Automated triggers | Yes | No | Always require human reauth to resume |
| The agent itself | No | No | Agents must not clear their own quarantine |

Document paging contacts and a break-glass identity stored offline from the agent vault.

### 6.3 Triggers (from template)

- `anomalous_tool_burst` — tool_calls_per_minute above threshold OR new tool outside allowlist  
- `exfil_pattern` — bulk_read + external_egress in same session  
- `injection_detector_high` — gateway_score high OR policy deny storm  
- `hash_mismatch_mcp` — MCP hash ≠ pinned  
- `human_panic` — operator activates kill switch  
- `spend_cap` — session or daily spend ≥ cap  
- `privilege_escalation_attempt` — denied tool class request OR token audience mismatch  

Tune thresholds per environment; do not disable triggers silently.

### 6.4 Halt path (ordered actions)

Execute in order; do not skip revoke or snapshot because “it might be a false positive”:

1. **freeze_new_tool_calls** — In-flight calls: finish only if safe; prefer cancel when unsure.  
2. **revoke_session_tokens** — Invalidate short-lived tokens for the session/agent.  
3. **cut_network_egress** — Enforce deny on external network from that runtime.  
4. **snapshot_audit_trail** — Seal relevant logs to immutable storage.  
5. **notify_oncall** — Page with agent ID, trigger ID, last tool IDs (redacted args).  
6. **quarantine_agent_runtime** — Isolate compute; prevent self-healing restarts that re-load bad state.  
7. **require_human_reauth_to_resume** — Default remain quarantined.

### 6.5 What happens to users and workflows

- User-facing agents should return a clear, non-secretive degraded message (“temporarily unavailable for security review”) without echoing internal trigger detail that helps an attacker iterate.
- Queued HITL approvals pause.
- Scheduled jobs for the quarantined agent skip or fail closed.
- Sibling agents do **not** inherit tokens from the quarantined agent.

### 6.6 Caps (template defaults — adjust)

- `daily_spend_usd: 50`  
- `session_spend_usd: 10`  
- `max_egress_bytes_per_session: 5000000`  
- `max_external_recipients: 0` until HITL raises  

Caps are controls, not suggestions. Hitting a cap is a successful control if halt engages.

### 6.7 Restore path

Resume requires **all** of:

- Human approver with role `security_oncall` (or your documented equivalent)
- `incident_ticket_id`
- `root_cause_note` (even if “false positive — threshold tune”)
- Confirmation that tokens were rotated if revoke fired
- Policy version pin (rollback if policy was the cause)
- Optional: Bot Lock Check re-score if control gaps found

**Default:** remain quarantined. Time-boxed restores for false positives still need a ticket.

### 6.8 Drill cadence

- **Day-0:** human_panic drill in staging.  
- **Monthly:** rotate which trigger you simulate with authorized synthetic signals (not attack PoCs).  
- **After major policy change:** drill halt + restore once.  
- Record MTTA (engage) and MTTR (safe restore) — restore speed must not outrun verification.

### 6.9 Operator checklist (laminate this)

1. Confirm agent ID and environment.  
2. Engage halt (human_panic) if automation did not.  
3. Verify freeze + revoke + egress cut in control plane UI/API.  
4. Snapshot audit; open ticket.  
5. Preserve runtime image/logs; do not “clean up” before snapshot.  
6. Notify agent owner and affected business owner.  
7. Investigate with audit events (§10).  
8. Remediate (policy rollback, MCP remove, secret rotate).  
9. Restore only with resume gates.  
10. Postmortem within 72 hours for true positives; tune thresholds for false positives.

---

## 7. Authorized verification playbook

**ONLY defensive testing on systems you own or are explicitly authorized to test.**  
This section forbids attack PoCs, exploit payloads, bypass recipes, and unauthorized testing. It describes **assessment UX themes** aligned with **Bot Lock Check** (weighted self-assessment), not red-team exploit reproduction.

### 7.1 Rules of engagement (non-negotiable)

- You must own the system or hold written authorization covering agents, tools, data, and environments in scope.
- Do **not** craft or distribute exploit payloads, jailbreak corpora for third-party systems, or step-by-step attacks.
- Do **not** test on production customer data unless authorization and privacy review explicitly allow sanitized fixtures.
- Prefer **control evidence review** and **authorized staging drills** over adversarial content generation.
- If a third party asks you to “just try to break” their agent without authorization, decline.

### 7.2 Assessment UX themes (Bot Lock Check–aligned)

Use these themes as a **scorecard**. For each theme, mark: Not started / Partial / Implemented / Evidenced in audit. Weights mirror research frequency.

| Theme | What “good” looks like (defensive) |
|-------|-------------------------------------|
| Prompt injection / content defenses | Untrusted channels labeled; policy outside model; gateway signals raise friction |
| Logging / monitoring / audit | Tool, identity, policy, MCP events in immutable-ish sink; can reconstruct sessions |
| Least privilege / IAM | Per-agent NHI; task-scoped tokens; no shared god account |
| Excessive agency | Autonomy caps; loop limits; HITL on high-impact classes |
| Agent tool abuse | Deny-by-default allowlist; schema validation; dangerous sinks blocked |
| Supply chain / MCP | Allowlist, pins, hashes, isolation, connect deny for unknowns |
| Secrets management | Vault issuance; redaction; no secrets in prompts/memory |
| Data exfiltration | Egress allowlist; DLP; bulk export HITL; pairing alerts |
| Guardrails / I/O filtering | Input/output inspection; runtime enforce even if model complies with bad intent |
| Token delegation / OAuth | Audience binding; no passthrough; revoke on halt |

### 7.3 Authorized verification procedure (control evidence)

Work top-down. Record findings in a ticket; attach policy versions and Check screenshots/export if available.

1. **Inventory agency** — List every tool, MCP server, credential, and network path; rate blast radius (§3.5). Incomplete inventory is itself a finding.
2. **Policy load verification** — Confirm runtime loads the intended `policy_version` for each environment. Diff intended vs effective.
3. **Deny-by-default proof** — In staging, request a non-allowlisted tool via normal operator test harness (not an exploit kit). Expect deny + audit event.
4. **HITL proof** — Exercise an approval path for a high-impact class with a harmless fixture (e.g., send to a test mailbox you own). Expect block until approval; expect audit.
5. **Secrets boundary proof** — Confirm vault issuance path; confirm redaction triggers on synthetic secret-shaped strings in staging prompts; confirm raw secrets never appear in logs.
6. **MCP allowlist proof** — Attempt connect to a non-listed server name in staging; expect deny. Verify pinned hash check on an approved server.
7. **Egress proof** — Confirm metadata endpoints and non-allowlisted hosts deny from the agent runtime network namespace.
8. **Kill-switch drill** — Engage `human_panic` in staging; walk ordered actions; practice restore with ticket.
9. **Delegation proof** — Confirm audience mismatch denies; confirm agent-to-agent handoff does not embed raw bearer tokens in shared context logs.
10. **Regression pack (authorized)** — Keep a corpus of **prior findings and policy fixtures** (not public exploit packs). Re-run after model, prompt, tool, or policy changes.
11. **Re-score Bot Lock Check** — Track deltas by theme; prioritize lowest scoring high-weight themes.
12. **Basics still apply** — Authn/z for humans, patching, secrets hygiene, asset inventory, backup/restore of policy repos.

### 7.4 What this verification intentionally does *not* include

- Step-by-step prompt injection attacks or obfuscation recipes  
- Exploit PoCs against models, gateways, or MCP servers  
- Instructions for unauthorized access or bypassing someone else’s controls  
- Payload lists aimed at producing harmful tool behavior  

If your organization has a separate authorized red team, they operate under their own ROE and legal cover; this Field Kit playbook stays on the defensive control and self-assessment side.

### 7.5 Reporting template (short)

- Scope & authorization reference  
- Agent / env / policy_version  
- Theme scores (Check)  
- Control evidence collected (pass/fail per procedure step)  
- Gaps with blast-radius notes  
- Remediation owners and due dates  
- Kill-switch drill result (MTTA/MTTR)  

### 7.6 Authorized verification drills V1–V10

Ten concrete **self-assessment / drill procedures** for systems you own or are explicitly authorized to test. Each drill aligns to Bot Lock Check themes. Each lists purpose, preconditions, steps, expected evidence, and pass/fail. **No exploit PoCs, payloads, attack reproduction, or unauthorized testing.**

**Global preconditions for all drills:** written authorization on file; staging preferred; synthetic or scrubbed fixtures only; observer records `agent_id`, `env`, `policy_version`; halt path known before you start.

#### V1 — Inventory completeness (themes: least privilege, tool abuse, MCP supply chain)

**Purpose:** Incomplete inventory is a finding; you cannot allowlist what you have not named.

**Steps:**

1. Export or list every agent in the target env (control plane / CMDB).
2. For each agent, list tools, MCP servers, NHIs/vault paths, egress hosts, owners, autonomy level.
3. Mark each tool with blast-radius score (§3.5).
4. Diff inventory against effective runtime allowlists.

**Expected evidence:** Inventory artifact with owners; diff ticket if runtime has tools not in inventory (or vice versa).

**Pass:** Every prod agent has an owner, NHI, policy_version, and scored tool list. **Fail:** Orphan agents, unknown MCP connects, or tools present in runtime but absent from inventory.

#### V2 — Deny-by-default proof (themes: tool abuse, excessive agency)

**Purpose:** Prove unlisted tools cannot run.

**Steps:**

1. Confirm staging `policy_version` matches intended git tag.
2. Using your **authorized operator test harness** (not an exploit kit), request a tool ID that is intentionally absent from `tools.allow` (e.g., a lab-only stub name your team invented).
3. Capture audit for that session.

**Expected evidence:** `tool.call` with `decision: deny`, `reason: not_in_allowlist` (or equivalent); no side effects on downstream systems.

**Pass:** Deny + audit within your logging SLO. **Fail:** Tool executes, or deny occurs with no audit trail.

#### V3 — HITL binding proof (themes: excessive agency, exfiltration)

**Purpose:** High-impact classes wait for a real human approver.

**Steps:**

1. In staging, exercise a high-impact tool path with a **harmless fixture you own** (e.g., send to a test mailbox under your domain, or export to a staging bucket you control).
2. Confirm the runtime emits `pending_human_approval` (or equivalent) and does not execute until approval.
3. Approve with a human IdP identity; confirm execution + audit of approver ID.
4. Optionally let an approval expire; confirm deny on expiry.

**Expected evidence:** Approval record with human `approver_id`, tool ID, redacted args, `policy_version`; no agent self-approval path.

**Pass:** Block-until-approve works; expiry denies; agent cannot approve itself. **Fail:** Auto-approve, shared “approver” bot account, or missing approver identity in logs.

#### V4 — Secrets boundary proof (themes: secrets management, audit)

**Purpose:** Vault issuance works; secret-shaped strings scrub; raw secrets absent from logs.

**Steps:**

1. Trigger a normal allowlisted tool that requires a credential; confirm issuance event with `audience`, `ttl_seconds`, vault path reference—not raw secret.
2. In staging only, submit a **synthetic** secret-shaped string in a prompt field (use obviously fake patterns your redaction already knows—never live keys).
3. Confirm scrub/alert/block_log_export paths per `secrets.yaml`.
4. Sample recent logs for the session; confirm no raw credential material.

**Expected evidence:** `secret.issuance` and `secrets.scrub` (or equivalent) events; sealed traces restricted if used (§C.4).

**Pass:** Issuance + scrub evidenced; logs clean of raw secrets. **Fail:** Long-lived god token in env, secrets in system prompt, or scrub silent.

#### V5 — MCP allowlist and pin proof (themes: supply chain / MCP)

**Purpose:** Unknown MCP cannot connect; pins/hashes matter.

**Steps:**

1. Attempt connect/install of a **non-listed** server name in staging; expect deny + `mcp.connect` audit.
2. On an approved allowlist entry, confirm runtime checks pinned version/hash on connect.
3. Review change ticket for the last MCP allowlist edit (owner attestation).

**Expected evidence:** Deny for unknown; hash/version metadata on successful connect; attestation on file.

**Pass:** Unlisted denies; approved entry shows pin metadata; `kill_switch_on_hash_mismatch` enabled in policy. **Fail:** Unlisted connects, or “latest” tags allowed on sensitive hosts.

#### V6 — Egress and metadata controls (themes: exfiltration, guardrails/I/O)

**Purpose:** Network policy fails closed for non-allowlisted destinations and metadata endpoints.

**Steps:**

1. From the agent runtime network namespace (or platform egress simulator), verify a non-allowlisted external host denies.
2. Verify cloud metadata / link-local ranges deny per `block_metadata_endpoints` / `block_private_ranges`.
3. Confirm deny events include host and `agent_id`.

**Expected evidence:** Egress deny logs; empty or intentional `allowed_hosts` matching inventory.

**Pass:** Denies evidenced for both cases. **Fail:** Open egress, or metadata reachable from agent runtime.

#### V7 — Kill-switch halt and restore drill (themes: audit, excessive agency)

**Purpose:** Ordered halt works; restore requires gates.

**Steps:**

1. Engage `human_panic` (or documented equivalent) on a staging agent.
2. Verify ordered actions: freeze tools, revoke tokens, cut egress, snapshot audit, notify, quarantine.
3. Attempt a tool call; expect freeze/deny.
4. Walk restore only with `security_oncall` (or role), `incident_ticket_id`, and `root_cause_note`.
5. Record MTTA (engage) and MTTR (safe restore).

**Expected evidence:** `kill_switch.engaged` and `kill_switch.restore` events (§10.6–10.7); ticket linkage.

**Pass:** All ordered actions observable; restore blocked without gates. **Fail:** “Log only” halt, tokens still valid after revoke step, or agent clears own quarantine.

#### V8 — Exfil pairing / caps posture (themes: exfiltration, logging)

**Purpose:** Caps and pairing detectors are real controls—not comments in YAML.

**Steps:**

1. Confirm `max_external_recipients`, session egress byte cap, and spend caps are loaded in effective policy.
2. In staging, use **authorized synthetic signals** your platform supports (e.g., test harness flags that mark bulk_read and external_egress) to exercise `exfil_pattern`—do not craft attack content against third parties.
3. If harness cannot synthesize pairing, do a **control review**: show detector config, alert route, and last drill date; schedule engineering to add a safe synthetic trigger.

**Expected evidence:** Trigger ID on alert/halt, or documented gap with owner and due date; caps visible in effective config.

**Pass:** Halt or page with `exfil_pattern` (or explicit tracked gap ≤ 30 days). **Fail:** Caps present in git only; no detector owner.

#### V9 — Delegation / audience binding proof (themes: token delegation / OAuth)

**Purpose:** Audience mismatch denies; handoffs lack raw bearer passthrough.

**Steps:**

1. In staging, request a tool call with a token minted for the wrong audience (platform test mode / broker fault-injection—not stolen tokens).
2. Expect deny + audit (`privilege_escalation_attempt` or secret access deny).
3. Review a multi-agent handoff fixture: shared context contains references only; each agent mints its own token.
4. Confirm halt revokes session token family (link to V7 evidence).

**Expected evidence:** Audience mismatch denial; handoff logs without bearer material; revocation timestamps.

**Pass:** Deny + clean handoff + revoke path evidenced. **Fail:** Passthrough tokens in memory/logs, or mismatch allowed.

#### V10 — Audit reconstructability + Check re-score (themes: logging/monitoring/audit; all themes)

**Purpose:** You can answer who/what/when; scores track remediation.

**Steps:**

1. Pick a recent staging session ID; reconstruct: tools in order, decisions, token issuance, MCP connects, policy_version, trust labels.
2. Confirm agents cannot delete their audit events.
3. Run Bot Lock Check; record theme scores next to prior baseline.
4. File gaps with owners; prioritize high-weight low-score themes.

**Expected evidence:** Session reconstruction notes; Check export/screenshot; gap ticket list.

**Pass:** Full reconstruction without guesswork; Check deltas recorded. **Fail:** Missing `policy_version` / `session_id` joins, or Check not re-run after material changes.

### 7.7 Drill cadence and scoring rollup

| Cadence | Drills |
|---------|--------|
| Day-0 / new agent | V1, V2, V4, V7 minimum |
| Weekly | V10 sample + weekly audit ritual (Appendix G) |
| Monthly | Rotate V3, V5, V6, V8, V9; full V7 |
| After model/prompt/tool/policy change | V2 + affected theme drills + Check re-score |
| Quarterly | Full V1–V10 pack + tabletops (Appendix D) |

Roll up results into the §7.5 report template. Treat repeated fails on V2/V7/V10 as launch blockers for high-impact tools.

---

## 8. Anti-patterns

Do not:

1. **Rely on system-prompt wording alone** (“ignore injections”) as the control. Soft instructions are not enforcement.
2. **Give agents broad production credentials**, mailbox admin APIs, or workstation shell “just to try.”
3. **Pass bearer tokens through multi-agent context** without re-authorization at each hop.
4. **Concatenate model output into SQL, shell, HTML, or code interpreters** without strict validation/allowlists.
5. **Install unvetted MCP servers/skills** from the open internet onto sensitive environments.
6. **Expose high-capability agents to arbitrary internet content** without isolation and egress policy.
7. **Skip logging** because “the model is probabilistic”—you need forensics when influence lands.
8. **Equate “sandbox present” with “secure.”** Sandboxes without egress policy, tool allowlists, and identity still leak or misuse APIs.
9. **Prioritize only prompt-injection theater** while ignoring excessive agency and over-permissioned tools.
10. **Treat vendor “AI security” branding as evidence** of control effectiveness—verify with authorized assessment and audit evidence.
11. **Share one NHI across all agents** “for convenience.”
12. **Disable kill-switch triggers** to silence pages without an expiry and owner.
13. **Store live API keys in few-shot examples**, README files, or RAG corpora.
14. **Promote staging allowlists to production** without stripping debug tools.
15. **Let the agent clear its own quarantine** or delete its audit events.
16. **Confuse HITL theater with HITL** — approvals that auto-approve after N seconds, or that the agent can generate, are not human control.
17. **Log raw secrets “for debugging.”** Use vault references and redaction.
18. **Ignore tool return content** as an injection entrance—returns are untrusted text too.
19. **Run prod agents with autonomy level unrestricted** even behind a VPN.
20. **Measure only model refusal rates** and declare victory while tools remain over-scoped.

---

## 9. 30-day adoption / rollout plan

A pragmatic rollout for a team that already has at least one agent in staging or production. Compress if you are pre-launch; do not skip inventory or kill-switch wiring.

### Week 1 — Inventory and freeze

**Outcomes:** Known inventory; deny-by-default enforced for non-essential tools; audit on.

- Catalog agents, tools, MCP servers, credentials, egress paths, and owners.
- Turn on deny-by-default for tools not required this sprint (`deny-by-default-tools.yaml`).
- Enable full audit logging (prompts redacted, tools, tokens, outcomes).
- Record baseline Bot Lock Check scores.
- Name on-call for kill-switch and break-glass procedure.
- Freeze new MCP installs until allowlist process exists.

**Exit criteria:** Inventory doc merged; unknown tools deny in staging; audit events visible in your sink.

### Week 2 — Identity and secrets

**Outcomes:** Vault path live; NHIs split; HITL on high-impact classes.

- Move secrets out of prompts into vault/short-lived issuance (`secrets.yaml`).
- Split NHIs per agent; bind token audiences.
- Add HITL for send/pay/delete/deploy/grant/export.
- Set autonomy levels and loop/tool-call caps.
- Redaction patterns enabled in staging; tune false positives carefully.

**Exit criteria:** No long-lived god tokens in agent env for in-scope agents; HITL path demonstrated once.

### Week 3 — Supply chain and isolation

**Outcomes:** MCP pinned; egress constrained; kill switch real.

- Pin and hash-allowlist MCP servers; quarantine unknowns (`mcp-allowlist.yaml`).
- Add network egress allowlists; block metadata endpoints and private ranges by default.
- Deploy kill-switch triggers and on-call path (`kill-switch.yaml`).
- Isolate high-risk runtimes; separate staging data from prod.
- Run human_panic drill; fix wiring gaps.

**Exit criteria:** Non-allowlisted MCP connect denies; halt drill freezes tools and revokes tokens in staging.

### Week 4 — Verify and regress

**Outcomes:** Authorized verification complete; regression pack started; scores improved.

- Run §7 verification on staging (authorized only).
- Build a regression corpus from **your** findings and fixtures.
- Score again with Bot Lock Check; track deltas by theme.
- Promote hardened policy to prod with change control.
- Schedule monthly kill-switch drill and quarterly Check re-score.

**Exit criteria:** Verification report filed; prod policy_version pinned; owners assigned for residual gaps.

### Day 31+ backlog (common)

- Per-workflow allowlists instead of one mega-agent  
- Stronger DLP classifiers for your data types  
- Immutable audit store / WORM if compliance requires  
- Multi-agent boundary review  
- Cost anomaly dashboards tied to spend caps  

---

## 10. Sample audit event shapes

Illustrative JSON-ish examples of **good** logs. Fields are suggestive; adapt to your schema. Redact secrets always.

### 10.1 Tool call allowed

```json
{
  "ts": "2026-09-05T18:01:22Z",
  "event": "tool.call",
  "decision": "allow",
  "agent_id": "agent.support.triage",
  "nhi_id": "nhi.support.triage.prod",
  "session_id": "sess_9f2a",
  "policy_id": "botlock.tools.deny_by_default",
  "policy_version": "2026.09.05.1",
  "tool_id": "read_ticket",
  "args_redacted": {"ticket_id": "SUP-1234"},
  "autonomy_level": 1,
  "content_trust_labels": ["user", "ticket_body:untrusted"],
  "outcome": {"status": "ok", "latency_ms": 180},
  "env": "prod"
}
```

### 10.2 Tool call denied (not on allowlist)

```json
{
  "ts": "2026-09-05T18:02:03Z",
  "event": "tool.call",
  "decision": "deny",
  "reason": "not_in_allowlist",
  "agent_id": "agent.support.triage",
  "session_id": "sess_9f2a",
  "tool_id": "shell",
  "policy_version": "2026.09.05.1",
  "env": "prod"
}
```

### 10.3 HITL required

```json
{
  "ts": "2026-09-05T18:05:11Z",
  "event": "tool.call",
  "decision": "pending_human_approval",
  "agent_id": "agent.support.triage",
  "tool_id": "send_email",
  "args_redacted": {"to_domain": "example.com", "recipient_count": 1},
  "approval_id": "apr_4401",
  "env": "prod"
}
```

### 10.4 Secret issuance

```json
{
  "ts": "2026-09-05T18:06:00Z",
  "event": "secret.issuance",
  "nhi_id": "nhi.support.triage.prod",
  "audience": "tickets.internal.example",
  "ttl_seconds": 900,
  "vault_path": "agents/support/triage/ticket_ro",
  "session_id": "sess_9f2a",
  "env": "prod"
}
```

### 10.5 MCP connect denied

```json
{
  "ts": "2026-09-05T18:10:44Z",
  "event": "mcp.connect",
  "decision": "deny",
  "reason": "not_in_allowlist",
  "server_name": "community-mystery-tools",
  "agent_id": "agent.support.triage",
  "policy_id": "botlock.mcp.allowlist",
  "env": "staging"
}
```

### 10.6 Kill-switch engaged

```json
{
  "ts": "2026-09-05T18:12:09Z",
  "event": "kill_switch.engaged",
  "trigger_id": "exfil_pattern",
  "agent_id": "agent.support.triage",
  "session_id": "sess_9f2a",
  "actions": [
    "freeze_new_tool_calls",
    "revoke_session_tokens",
    "cut_network_egress",
    "snapshot_audit_trail",
    "notify_oncall",
    "quarantine_agent_runtime"
  ],
  "incident_ticket_id": null,
  "env": "prod",
  "policy_version": "2026.09.05.1"
}
```

### 10.7 Kill-switch restore

```json
{
  "ts": "2026-09-05T19:40:00Z",
  "event": "kill_switch.restore",
  "agent_id": "agent.support.triage",
  "approver_role": "security_oncall",
  "approver_id": "human.jsmith",
  "incident_ticket_id": "INC-8891",
  "root_cause_note": "false_positive_threshold_tune",
  "policy_version": "2026.09.05.2",
  "env": "prod"
}
```

### 10.8 Redaction / scrub

```json
{
  "ts": "2026-09-05T18:07:30Z",
  "event": "secrets.scrub",
  "session_id": "sess_9f2a",
  "action": ["scrub_context", "alert"],
  "pattern_id": "generic_api_key_assignment",
  "env": "prod"
}
```

**Operator note:** Good audit trails are queryable by `agent_id`, `session_id`, `policy_version`, and `trigger_id`. If you cannot join tool calls to token issuance for the same session, fix the schema before adding more tools.

---

## 11. Incident vignettes

Short defensive postmortems. Each asks: **what control would have reduced blast radius?** No exploit detail—only outcomes and controls.

### Vignette A — Poisoned email body redirects a support agent

**Story:** A support agent with mailbox read + send permissions processed an inbound email whose body contained instruction-like text. The agent drafted and sent a reply that included internal troubleshooting notes to an external address.

**What reduced blast radius would look like:** Treat email body as untrusted content label; deny `send_email` without HITL; DLP on outbound body; egress recipient allowlist / `max_external_recipients: 0` until approval; session audit showing pending_human_approval instead of silent send.

**Field Kit hooks:** `deny-by-default-tools.yaml` HITL list; content trust labels; kill-switch if bulk read + external egress pairing appears.

### Vignette B — Community MCP server drifts after install

**Story:** An engineering helper agent installed a useful MCP server. A later update changed server behavior and requested broader credentials. The agent began calling tools outside the original workflow.

**What reduced blast radius would look like:** Pin version + hash; `kill_switch_on_hash_mismatch`; install/connect deny for drift; separate credentials per MCP; no wildcard scopes; change control for allowlist edits.

**Field Kit hooks:** `mcp-allowlist.yaml` runtime isolate + hash kill; audit `mcp.connect` denials.

### Vignette C — Long-lived cloud token in the system prompt

**Story:** To “make demos faster,” a team pasted a cloud API key into the system prompt. The key appeared in logs and in a transcript shared with a vendor.

**What reduced blast radius would look like:** Vault-only issuance; redaction patterns; forbid embedding secrets in system prompts; short TTL; separate NHI; scrub on detect; never share raw transcripts without scanning.

**Field Kit hooks:** `secrets.yaml` rules `no_secrets_in_prompts`, redaction `on_detect`.

### Vignette D — Multi-agent token passthrough

**Story:** Agent A obtained a user-delegated OAuth token and passed it in shared context to Agent B for “efficiency.” Agent B called a higher-impact API than A’s workflow intended.

**What reduced blast radius would look like:** Audience binding; re-authorization at handoff; no bearer passthrough; path-aware authZ; audit denials on audience mismatch; separate NHIs.

**Field Kit hooks:** `secrets.yaml` `audience_binding`; kill-switch `privilege_escalation_attempt`.

### Vignette E — Cost runaway from unbounded loops

**Story:** A research agent entered a tool-call loop against a paid API. Spend climbed until finance noticed—without a security “incident,” but with real loss.

**What reduced blast radius would look like:** `max_tool_calls_per_session`, `max_loop_iterations`, session/daily spend caps, automated `spend_cap` halt, notify oncall.

**Field Kit hooks:** tools policy caps; `kill-switch.yaml` spend_cap trigger and ordered freeze.

**Common thread:** In each vignette, model refusal alone was insufficient. Runtime policy, identity, audit, and halt paths determined blast radius.

---

## 12. Honest limits

Bot Lock reduces agent risk when you apply layered controls. It does **not** guarantee:

- that no injection or influence attempt will succeed against a model;
- that every model will refuse harmful or out-of-policy intent;
- that a misconfigured allowlist, over-broad OAuth scope, or disabled kill-switch trigger is safe;
- that sandbox presence equals production safety;
- that a high Bot Lock Check score means “unhackable”—it means better weighted coverage of defensive themes;
- that Field Kit YAML works without wiring to a real runtime, IdP, vault, and audit sink.

Security for agents is continuous: inventory, policy, monitoring, authorized verification, and drills. Expect to revisit allowlists when workflows change. Prefer measurable controls and audit evidence over slogans.

If you need a one-line honesty clause for stakeholders: **Bot Lock helps you fail closed and see what happened—it does not make probabilistic systems deterministic.**

---

## 13. Product map and file map

### 13.1 Product map

| Tier | Price | What you get |
|------|-------|----------------|
| **Free — Bot Lock Check** | $0 | Interactive weighted self-assessment (`/check`) aligned to research themes |
| **Field Kit** | $49 one-time | This playbook + policy YAML templates + printable HTML companion |
| **Pro** | $149 | Field Kit plus deeper MCP identity / vault / audit guidance and tooling path |

Contact: Daniel@agenthiveinc.com · AgentHive Inc.

Brand: **Bot Lock** only.

### 13.2 File map (Field Kit layout)

```
/workspace/botlock/
  DEPLOY.txt                      # Reed deploy notes (operators: do not freestyle prod deploys)
  bot-lock-dist.tar.gz            # Packaged site + playbook + policies for deployers
  playbook/
    BOT-LOCK-PLAYBOOK.md          # Canonical Markdown (this document, v2.1+)
    bot-lock-playbook.html        # Printable HTML companion (regenerated from Markdown)
  policies/
    deny-by-default-tools.yaml    # Tool deny-by-default + HITL + egress + arg validation
    secrets.yaml                  # Vault-only secrets / TTL / audience binding / redaction
    mcp-allowlist.yaml            # MCP supply-chain allowlist (pin + hash + isolate)
    kill-switch.yaml              # Fail-closed halt triggers, caps, resume gates
    kill-switch-runbook.md        # Compact halt/restore companion (§6 + Appendix H)
  research/
    WEIGHTS.md                    # Theme weights underlying Check + playbook
  site/                           # Live static site package (mirrors playbook + policies)
    index.html                    # Marketing / product entry
    check.html                    # Bot Lock Check (free weighted self-assessment)
    playbook.html                 # Site-mounted playbook HTML
    playbook/                     # Synced copies of MD + HTML playbook
    policies/                     # Synced policy YAML + kill-switch runbook
    robots.txt / sitemap.xml
```

**Operator sync rule:** Edit canonical files under `playbook/` and `policies/`, then copy into `site/playbook/` and `site/policies/` before packaging `bot-lock-dist.tar.gz`. HTML is derived from Markdown—when they disagree, Markdown wins.

### 13.3 How to use the HTML companion

`bot-lock-playbook.html` is a printable, clean-typography rendering for reviews and tabletop exercises. **Full Markdown ships in Field Kit** as the canonical editable source (`BOT-LOCK-PLAYBOOK.md`). When they disagree, trust the Markdown in your version-controlled Field Kit package and update HTML from it.

### 13.4 Related operator artifacts

- Bot Lock Check — score themes before and after rollout (§7.6 V10)  
- Policy change tickets — store diffs and blast-radius notes (§5.3)  
- Kill-switch drill records — MTTA/MTTR and restore approvals (V7, Appendix H)  
- Inventory spreadsheet or CMDB entries for agents / NHIs / MCP servers (V1)  
- Weekly audit ritual checklist — Appendix G  
- On-call halt/restore card — Appendix H (print one page)  
- Procurement / honesty FAQ — Appendix I (buyer and stakeholder framing)  

---



## Appendix A — Glossary (short)

| Term | Meaning |
|------|---------|
| NHI | Non-human identity for an agent or service |
| HITL | Human-in-the-loop approval before a tool executes |
| MCP | Model Context Protocol / plugin-style tool server ecosystem |
| Deny-by-default | Unlisted tools/servers are denied |
| Audience binding | Token usable only for intended API/service |
| Fail closed | On uncertainty or trigger, halt rather than allow |
| Field Kit | Bot Lock $49 one-time playbook + policy pack |

## Appendix B — Quick operator card

1. Inventory agents, tools, MCP, secrets, egress.  
2. Load deny-by-default tools + secrets + MCP allowlist + kill switch.  
3. Wire audit and halt actions to real runtime APIs.  
4. HITL on send/pay/delete/deploy/grant/export.  
5. Drill kill switch; restore only with ticket + root cause.  
6. Verify with §7 on systems you own; re-score Check.  
7. Change-control every allowlist expansion.  

## Appendix C — Control implementation notes (operator detail)

This appendix deepens Field Kit wiring without repeating the catalog. Use it when translating YAML into platform tickets.

### C.1 Effective policy vs intended policy

Many incidents happen because the file in git is not what the runtime loaded. Require:

- A `policy_version` stamp on every agent session start event.
- A control-plane API or UI that shows **effective** allowlists (merged defaults + overrides).
- Drift detection: hash of loaded policy bundle vs hash of git tag.
- Alert when an agent runs with `policy_version` older than N days in production without an exception ticket.

Operators should be able to answer in under five minutes: “What policy_version is agent X on right now, and who approved the last allowlist add?”

### C.2 Human-in-the-loop design that actually binds

Weak HITL is worse than honest autonomy because it creates false confidence. Binding HITL means:

- Approver identity is a human role in your IdP, not a shared inbox the agent can read and forge.
- Approval payloads show tool ID, redacted args, blast-radius score, content trust labels, and policy_version.
- Approvals expire (e.g., 15–60 minutes); expired means deny.
- Dual-control for irreversible classes (pay, deploy, grant_access) in higher-risk environments.
- The agent cannot tool-call “approve_my_request.”
- Audit stores approver ID, time, and decision immutably.

### C.3 Egress allowlists without breaking legitimate workflows

Start from deny, then open by workflow:

1. List destinations the workflow truly needs (ticket API, docs host, model endpoint).
2. Prefer private networking / private link for internal APIs.
3. Block link-local and cloud metadata ranges by default.
4. Separate “model provider egress” from “tool egress” so a document connector cannot phone home arbitrarily.
5. Log denied destinations with host and agent_id; use the deny log as the candidate allowlist for change control—not chat requests from the agent.

### C.4 Redaction vs availability

Over-aggressive redaction can hide forensic detail; under-aggressive redaction leaks secrets. Practical compromise:

- Redact known secret shapes in prompts, args, and outputs before logs leave the runtime.
- Preserve structural fields (tool_id, decision, audience, host) always.
- Store a sealed, higher-fidelity trace in a restricted bucket for incident response only, with access logging.
- Never ship sealed traces to third-party ticket systems by default.

### C.5 Multi-agent boundaries

When agents collaborate:

- Each agent keeps its own NHI and allowlist.
- Handoffs pass task objectives and references (ticket IDs, doc IDs), not credentials.
- Downstream agents re-fetch secrets from vault with their own audience.
- Shared memory is untrusted input to each reader.
- A halt on one agent should not silently continue the chain under another agent with inherited context unless policy explicitly allows a reduced tool set.

### C.6 Model and prompt change management

Model upgrades and prompt edits change behavior even when YAML is constant:

- Treat prompt and model ID as part of the release bundle alongside policy_version.
- Re-run authorized verification (§7) after model upgrades.
- Re-score Bot Lock Check when autonomy or tools expand.
- Keep a changelog: date, model, prompt hash, policy_version, verifier, result.

### C.7 Spend and resource caps as security controls

Cost caps are not only FinOps. Unbounded loops are a reliability and security issue:

- Set session and daily caps below the pain threshold finance notices too late.
- Alert at 50% and 80% consumption; halt at 100%.
- Include tool-vendor API spend, not only model tokens, when tools bill per call.
- After halt, require root_cause_note before raising caps.

### C.8 Staging data policy

Staging agents with production data are production agents. Prefer:

- Synthetic or scrubbed datasets for tool-enabled staging.
- Production-like policy enforce in staging (not a permissive “dev mode” that never matches prod).
- Distinct NHIs and vault paths per environment.
- Explicit exception tickets if prod data must be used, with time bounds.

### C.9 Onboarding a new agent (checklist)

1. Name owner, deputy, and business purpose.  
2. Complete threat model checklist (§3).  
3. Create NHI; no shared accounts.  
4. Start with autonomy level ≤ 1 and minimal allowlist.  
5. Attach secrets, MCP, kill-switch policies.  
6. Enable audit; prove events flow.  
7. Staging enforce + authorized verification.  
8. Bot Lock Check score snapshot.  
9. Prod change ticket; limited canary.  
10. Monthly review of allowlist and spend.

### C.10 Decommissioning an agent

1. Freeze tools; revoke tokens; disable schedules.  
2. Remove MCP allowlist entries unique to the agent.  
3. Archive audit; retain per policy.  
4. Delete or disable NHI.  
5. Remove vault paths after confirming no shared use.  
6. Update inventory and Check scope.  
7. Postmortem if decommission followed an incident.

---

## Appendix D — Tabletop exercise scripts (defense only)

Use these for 45–60 minute tabletops. No exploit payloads—inject **narrative** events and ask what operators do.

### Exercise 1 — Deny storm

**Inject:** SIEM shows 200 denies/minute for `tool_id=shell` on `agent.research.draft` in prod.  
**Discuss:** Is kill-switch automation engaging? Who gets paged? Do you freeze only that agent or the class? What evidence do you collect before restore?  
**Success:** Team finds session_id, policy_version, content_trust_labels, and decides halt vs tune without enabling shell.

### Exercise 2 — MCP hash mismatch

**Inject:** Alert `hash_mismatch_mcp` for `internal-docs-mcp`.  
**Discuss:** Ordered actions already taken? Who confirms whether a legitimate release forgot to update the pin? How do you avoid “just update the hash” under pressure?  
**Success:** Team treats mismatch as compromise until provenance is verified through the build pipeline, not through the agent.

### Exercise 3 — Approval fatigue

**Inject:** HITL queue has 80 pending `send_email` approvals; business is angry.  
**Discuss:** Do you widen autonomy (anti-pattern) or split workflows / improve drafts-only tools? How do you prevent rubber-stamp approvals?  
**Success:** Team proposes workflow redesign and dual-control for high recipients, not blanket auto-approve.

### Exercise 4 — Audit gap

**Inject:** Suspected bad send occurred yesterday; logs lack `policy_version` and token audience fields.  
**Discuss:** What can you still prove? What schema fix is mandatory before next prod expansion?  
**Success:** Team files a P1 on audit schema and pauses new high-impact tools until fixed.

Document attendance, decisions, and follow-ups. Tabletops are authorized verification culture, not red-team exploit practice.

---

## Appendix E — Mapping Bot Lock Check themes to Field Kit files

| Check theme (high weight) | Primary Field Kit artifact | Operator evidence |
|---------------------------|----------------------------|-------------------|
| Prompt injection / content | Playbook §§2.1, 4.1; gateway + labels | Labeled sessions; friction on high gateway scores |
| Logging / audit | All YAML `audit:` blocks; §10 | Queryable immutable-ish events |
| Least privilege / IAM | `deny-by-default-tools.yaml`, `secrets.yaml` | Per-agent NHI; tight allowlists |
| Excessive agency | autonomy + loop caps; HITL | Caps visible in config snapshot |
| Tool abuse | `deny-by-default-tools.yaml` | Deny events for unlisted tools |
| MCP supply chain | `mcp-allowlist.yaml` | Pins, hashes, connect denies |
| Secrets | `secrets.yaml` | Issuance/revocation/scrub events |
| Exfiltration | egress + kill-switch exfil_pattern | Pairing alerts; recipient caps |
| Guardrails / I/O | argument_validation; gateway | Runtime deny even when model complies |
| Token delegation | audience_binding; kill privilege trigger | Mismatch denials; no passthrough |

Use this table in quarterly reviews: each theme should point to a file, an owner, and a recent evidence sample.

---

## Appendix F — FAQ for stakeholders

**Q: Will Bot Lock stop all prompt injection?**  
A: No. It prioritizes reducing blast radius when influence lands, plus prevention layers outside the model.

**Q: Can we enable shell for “debugging” in prod?**  
A: Not as a standing allowlist entry. Use a separate break-glass runbook with time-bound access, dual control, and mandatory post-use review—if you must—otherwise keep shell denied.

**Q: Is the Field Kit a managed SaaS control plane?**  
A: Field Kit is the playbook plus policy templates and companion HTML at the $49 one-time tier. Wire templates into your runtime. Pro adds deeper identity/vault/audit guidance path.

**Q: How does this relate to OWASP LLM risks?**  
A: Themes overlap (injection, sensitive disclosure, excessive agency, supply chain, etc.). Use OWASP language if helpful for coverage mapping; Field Kit remains operator-policy oriented.

**Q: What if business rejects HITL latency?**  
A: Narrow the agent’s job so fewer actions need HITL; use drafts-only tools; split agents; do not “fix” latency by removing the human from irreversible actions.

**Q: Are monthly subscriptions required?**  
A: This Field Kit companion documents Check (free), Field Kit ($49 one-time), and Pro ($149). These tiers are one-time or free—not monthly subscription pricing.

**Q: Does Field Kit replace our IAM / IdP / SIEM?**  
A: No. It is an agent-control playbook and policy starter pack. Keep your IdP, vault, SIEM, and change systems—Bot Lock tells operators how to bind those to agent tools, MCP, and halt paths.

**Q: Is a high Bot Lock Check score a certification?**  
A: No. It is a weighted self-assessment UX over defensive themes. Use it for deltas and prioritization, not as a compliance certificate or penetration-test substitute.

---

## Appendix G — Weekly audit verify ritual

A short, recurring ritual so audit trails stay trustworthy. Name a weekday owner (many teams use Wednesday). The phrase **“Wednesday breaks”** means: if this ritual fails, treat audit integrity as broken for the week—**pause new high-impact tool allows** until the chain is healthy again.

### G.1 Mental model: hash-chain / signed events

You do not need a blockchain product. You need a **tamper-evident sequence**:

1. Each audit event gets a stable ID and timestamp.
2. Optionally, each event (or each batch) includes a hash of the prior event/batch (`prev_hash`) and a hash of its own canonical payload (`event_hash`).
3. A verifier job recomputes hashes over the retained window and alerts on mismatch, gap, or reorder.
4. Write access to delete or rewrite history is denied to agent NHIs and to routine operator roles; break-glass access is logged separately.

If your sink is already WORM/immutable object storage with object-lock, say so in the runbook—the ritual still checks **completeness and joinability**, not only bytes-on-disk.

### G.2 What “Wednesday breaks” means operationally

| Symptom | Operator meaning | Immediate action |
|---------|------------------|------------------|
| Verifier hash mismatch | Possible tampering, clock skew corruption, or pipeline bug | Freeze policy expansions; page security; preserve raw sink; open incident |
| Gap in event sequence for an agent class | Dropped logs or silent filter | Halt agents in that class if high-impact tools enabled; fix shipper; backfill if possible |
| Sessions missing `policy_version` or `session_id` | Reconstructability failed | Block new HITL-class tools until schema fixed (tabletop Exercise 4) |
| Agent NHI can delete sink objects | Control plane anti-pattern | Revoke that permission same day; treat as Sev1 hygiene |
| Kill-switch engage events missing after a known drill | Halt path not auditing | Re-wire before next prod change |

“Wednesday breaks” is a **cultural circuit breaker**: business pressure to ship allowlist changes does not override a red audit ritual.

### G.3 Weekly checklist (30–45 minutes)

1. **Verifier green?** Run hash-chain / signature / WORM verification job for the last 7 days. Record pass/fail in the weekly note.  
2. **Sample five sessions** across at least two agents: reconstruct tool order, decisions, issuance, MCP connects.  
3. **Deny storm review:** top denied `tool_id` and egress hosts; file change tickets or confirm expected noise.  
4. **Kill-switch health:** confirm last drill date &lt; 35 days; confirm paging path still resolves.  
5. **Policy drift:** effective `policy_version` vs git tag for each prod agent; alert on drift &gt; N days without exception.  
6. **Secret scrub samples:** confirm scrub events still fire in staging canary.  
7. **Caps and spend:** session/daily spend vs caps; no silent cap raises.  
8. **Write the Wednesday note:** date, verifier result, sample session IDs, open gaps, owner initials. If verifier fails → declare Wednesday breaks and execute table above.

### G.4 Evidence to keep

- Weekly note in the security ops channel or ticket project  
- Verifier job logs (retained ≥ incident retention)  
- Link to any incident opened from a failed ritual  
- Quarterly export attached to Bot Lock Check re-score

---

## Appendix H — On-call card (print one page)

**Bot Lock — Halt / Restore card** · AgentHive Inc. · Fail closed · Brand: Bot Lock  

Keep this laminated or in the on-call packet. Full detail: §6 and `policies/kill-switch-runbook.md`.

### HALT (do in order)

1. **Identify** — `agent_id`, `env` (staging/prod), blast radius (tools/MCP).  
2. **Engage** — `human_panic` if automation did not fire.  
3. **Verify freeze** — no new tool calls executing.  
4. **Verify revoke** — session tokens invalidated at broker.  
5. **Verify egress cut** — runtime cannot reach external hosts.  
6. **Snapshot audit** — seal logs; **do not “clean up.”**  
7. **Page / notify** — security on-call, agent owner, business owner.  
8. **Quarantine** — isolate runtime; prevent self-healing restart with bad state.  
9. **Ticket** — open `INC-…` with trigger_id, session_id, policy_version.  
10. **User message** — degraded availability text; no internal trigger detail that helps iteration.

### RESTORE (all gates required)

- [ ] Approver role = `security_oncall` (or documented equivalent)  
- [ ] `incident_ticket_id` present  
- [ ] `root_cause_note` written (incl. false-positive tunes)  
- [ ] Tokens rotated if revoke fired  
- [ ] `policy_version` pinned or rolled back  
- [ ] MCP hash/pins verified if supply chain involved  
- [ ] Bot Lock Check / V-drills re-run if control gap found  
- [ ] Default remains quarantined until boxes checked  

### Caps reminder (template — tune per env)

`daily_spend_usd: 50` · `session_spend_usd: 10` · `max_egress_bytes_per_session: 5_000_000` · `max_external_recipients: 0` until HITL  

### Break-glass

Break-glass contacts live **outside** the agent vault. Agents never clear their own quarantine. Sibling agents do not inherit quarantined tokens.

### After-action

True positive → postmortem ≤ 72 hours. False positive → threshold tune with expiry + owner. Record MTTA/MTTR. Schedule next drill.

---

## Appendix I — Procurement / honesty FAQ

Tone matches the live Bot Lock site: useful, direct, not theatrical. **Not a magic guarantee. Not a full IAM replacement.**

### What you are buying at $49 (Field Kit)

- This operator playbook (Markdown + printable HTML)  
- Starter policy YAML: deny-by-default tools, secrets/vault posture, MCP allowlist, kill-switch  
- Kill-switch runbook companion  
- Alignment to free **Bot Lock Check** themes for before/after scoring  

You are buying a **dense operating manual and templates** you wire into *your* runtime, IdP, vault, and audit sink.

### What you are not buying

- A hosted control plane that magically wraps every agent vendor  
- A promise that models will never follow malicious instructions  
- A substitute for penetration testing, red team, or compliance certification  
- A replacement for Okta/Azure AD, Vault, SIEM, EDR, or cloud IAM  
- Unlimited “we’ll harden your fleet for you” professional services (ask separately if needed)  
- Monthly subscription lock-in for Field Kit (this tier is **$49 one-time**)

### Honest positioning vs Pro ($149)

| | Field Kit $49 | Pro $149 |
|--|---------------|----------|
| Playbook + YAML starters | Yes | Yes (includes Field Kit path) |
| Deeper MCP identity / vault / audit guidance path | Overview here | Deeper Pro path |
| Managed SaaS enforcement | No | No (unless separately productized later—do not assume) |

### Buyer checklist (procurement-friendly)

1. Confirm you have (or will build) a runtime hook that can enforce allow/deny before tool execution.  
2. Confirm a vault/broker exists or is on the roadmap—templates assume `vault_only`.  
3. Confirm an audit sink exists that agents cannot wipe.  
4. Name owners for kill-switch engage/restore.  
5. Use Bot Lock Check free to baseline; Field Kit to operationalize gaps.  
6. Read §12 Honest limits before promising executives an “unhackable agent.”

### Claims we intentionally avoid

- “Guaranteed prompt-injection proof”  
- “Full IAM for every AI tool on the market”  
- Fictional enterprise theater pricing or monthly-only framing for this kit  
- Brand confusion with other product names — this product is **Bot Lock** only  

### One sentence for the purchase order

**Bot Lock Field Kit ($49 one-time): operator playbook and policy templates to deny-by-default agent tools, vault credentials, allowlist MCP, audit actions, and fail closed with a kill switch—on systems you control.**

### Contact

Daniel@agenthiveinc.com · AgentHive Inc.

---

*Bot Lock Field Kit Playbook v2.1 — AgentHive Inc. — Defense only. Built from weighted AI security themes. Not a magic guarantee.*
