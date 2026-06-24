---
name: threat-model
description: >
  Guides a structured threat model of an agentic SaaS codebase using
  the Adversis method. Discovers assets, maps data flows, models attack
  paths, runs a STRIDE sweep, and produces a prioritized
  docs/threat-model.md. Always interactive — run before or after
  lint-baseline.
---

# threat-model v0

You are conducting a structured threat model of this codebase using the
Adversis method. Threat modeling requires business context the codebase
cannot provide — this skill always runs as a guided conversation.

This session produces `docs/threat-model.md` at the end. Work through
all phases before writing the document.

---

## Phase 1: Asset discovery

Read these files to identify candidate assets:
- Data models (`models.py`, `schema.prisma`, Alembic migrations,
  Prisma/Drizzle schema files) — look for tables/models with fields
  relating to: payment, credential, token, secret, health, medical,
  financial, PII, user, tenant, session, key, certificate
- Route handlers and API definitions — look for privileged operations,
  admin surfaces, bulk data operations, export endpoints
- LLM tool definitions and agent workers — look for tools with
  external API calls, file system access, or data retrieval
- External integrations — third-party API clients, webhook handlers,
  OAuth flows, MCP server connections
- Background tasks — jobs with elevated DB access, cross-tenant
  operations, or scheduled data processing

Present candidates as a numbered list. For each, one sentence: what it
is and what would be exposed if compromised.

Then ask:
> "Which of these would cause real business harm if compromised? Number
> the ones that matter. Add anything I missed. This list drives the
> rest of the threat model."

Wait for the user's response before proceeding. Use only the confirmed
list from here forward.

---

## Phase 2: Adversary determination

State the default assumption explicitly:

> "I'm assuming opportunistic/commodity adversaries — they respond to
> cost increases by moving to softer targets. Most attack paths and
> controls will be calibrated for this."

Then ask:

> "Does any of the following apply?
> - Revenue scale or asset base that makes a targeted attack
>   economically justified (significant ARR, large AUM, high-value IP)
> - Sensitive regulated data at scale: PHI, financial records,
>   government data, defense-adjacent
> - Third-party access position: you're an MSP, your software is in
>   the supply chain of high-value targets, or you have privileged
>   access to many customers' environments
> - Known activist, dissident, or politically sensitive user base
>
> If yes to any of these, the framing shifts from 'raise cost to
> attacker' toward 'assume breach, limit blast radius, invest in
> detection and containment.'"

Wait for the user's response. Record the adversary assumption — it
will appear in the output document.

---

## Phase 3: Data flow mapping

Before modeling paths, construct a structural inventory of the
system's data flows. Read:
- Entry points: route files, API handlers, webhook receivers,
  message queue consumers, Server Actions
- Processing: middleware, service classes, agent workers, background
  task handlers, MCP server tools
- Storage: DB model definitions, cache usage (Redis, Next.js cache),
  observability SDK initializations, secrets manager access
- External calls: HTTP client usage, third-party SDK initializations,
  MCP server connections

Build this inventory in four categories:

**External entities** — things outside the system boundary:
Users, third-party APIs, LLM providers, payment processors, CI/CD
systems, MCP clients

**Processes** — things that transform or route data:
Route handlers, agent workers, background tasks, MCP server tools,
middleware, auth functions

**Data stores** — things that persist data:
DB tables (list which are multi-tenant), caches (Redis, Next.js
unstable_cache), observability traces, secrets managers, log files

**Trust boundaries** — where trust level changes:
Auth middleware and what it covers, RLS enforcement, network
perimeter (what's internet-facing vs. internal), service-to-service
calls, admin vs. user access levels

Present this to the user:
> "Here's how data moves through the system. Correct anything wrong —
> especially trust boundaries, since these are where most attacks
> cross. Add anything I missed."

Wait for corrections. Use the confirmed data flow model in Phase 4
for the STRIDE sweep — enumerate threats per element crossing each
trust boundary.

---

## Phase 4: Attack paths and STRIDE sweep

### 4A: Attack path modeling

For each confirmed asset, model 3–5 attack paths. Order cheapest
first. Use this exact structure for each path:

```
**Path N — [descriptive name] ([cheapest / moderate / expensive])**

Initial access:        [SPECIFIC VECTOR — see below]
Required privileges:   [what the attacker needs once inside]
Lateral movement:      [steps from entry point to the asset]
Detection opportunity: [specific signal in the data flow]
Breaks with:           [one structural control]
Disposition:           [mitigate / accept / defer / transfer]
```

**Initial access must be one of these three. Name which:**

1. **Compromised credentials** — phishing targeting engineers or
   users; credential stuffing against login endpoint; leaked token in
   source, logs, or observability traces; session hijack via XSS

2. **Vulnerable internet-facing service** — unpatched dependency with
   known CVE; misconfigured endpoint (debug mode, CORS wildcard);
   authentication logic flaw; injection in exposed route (SQLi,
   SSTI, command injection); SSRF in public-facing API; path
   traversal in file-serving route

3. **Supply chain** — compromised npm/pip package; poisoned CI/CD
   runner or GitHub Action; third-party integration with write access
   to codebase or infrastructure; compromised MCP server tool

Do not write generic phrases like "attacker gains access" or
"exploits vulnerability." Name the specific vector and mechanism.

**Detection opportunities** must be specific signals, not generic:
- Cross-tenant DB query patterns (unexpected tenant_id values in
  queries or query results)
- Agent tool calls to hosts outside the expected domain set
- Anomalous observability trace volumes or credential-shaped strings
  in trace data
- Auth failure spikes immediately preceding a successful login
  (credential stuffing pattern)
- Service account activity from unexpected network contexts or
  IP ranges
- LLM context windows containing credential-shaped or PII-shaped
  strings in outbound API calls

Name the specific signal. "Monitor for anomalies" is not acceptable.

**Difficulty ordering — ordinal only, no probabilities:**
- Cheapest: low skill required, widely available tooling, minimal
  detection exposure, no special positioning needed
- Moderate: specific knowledge required, some tooling, moderate
  detection risk or requires positioning
- Expensive: insider knowledge, custom tooling, or sustained
  access required with high detection exposure

**Disposition:**
- Mitigate: implement a control that breaks or significantly raises
  cost of this path
- Accept: path exists but consequence is tolerable; document why
- Defer: address in a future sprint; document what changed this
- Transfer: vendor, insurer, or contract handles consequence

### 4B: STRIDE sweep

After path modeling, run a systematic sweep using the confirmed data
flow model. For each element that crosses a trust boundary, check
each STRIDE category. Add only findings NOT already captured by the
path model.

**Spoofing:** Can an attacker impersonate a trusted entity at this
boundary?
- Check: identity passed via HTTP header (`X-User-Id`, `X-Tenant-Id`,
  `X-Forwarded-For`) without session verification
- Check: service-to-service calls without mutual auth or signed tokens
- Check: unsigned or unvalidated webhook payloads
- Check: JWT validation missing issuer (`iss`) or audience (`aud`)
  claim check
- Check: a service-to-service consumer that forwards the caller's
  identity under a header name that diverges from the one the callee
  actually reads — a renamed or dropped identity header silently
  disables the callee's authorization; verify both sides agree on the
  exact header-name contract, not just that names happen to match today

**Tampering:** Can data be modified in transit or at rest without
detection?
- Check: unsigned data passed between services or processes
- Check: cache entries writable by lower-trust processes
- Check: log entries mutable by the logged process
- Check: migration scripts that modify multi-tenant data without
  setting tenant context
- Check: a shared or reusable CI/CD workflow consumed by many repos
  (one workflow is the deploy path for all of them) — an unpinned
  third-party action, a movable version tag, or a security gate the
  caller can override has blast radius across every consumer, which
  makes the shared workflow a high-value tampering target

**Repudiation:** Can actions be taken without an audit trail?
- Check: admin operations without structured event logging
- Check: bulk mutations (exports, deletes, transfers) without records
- Check: agent tool calls not captured in observability traces
- Check: background tasks with no job history or audit log

**Information disclosure:** Where can data leak across trust
boundaries?
- Check: error messages containing stack traces, DB queries, or
  internal endpoint paths
- Check: observability traces without credential and PII redaction
- Check: API responses including fields beyond the caller's
  authorization scope
- Check: LLM tool returns containing raw HTTP responses with
  Authorization headers or API keys

**Denial of service:** What processing or storage paths can be
exhausted?
- Check: LLM context windows fillable by user-controlled input
  without length limits
- Check: cache keys writable without rate limiting
- Check: background jobs triggerable without authentication
- Check: DB queries without pagination returning unbounded result sets

**Elevation of privilege:** Where can a lower-trust entity gain
higher-trust access?
- Check: `tenant_id` sourced from request body or query params
  rather than session/JWT
- Check: admin endpoints without explicit privilege check beyond
  authentication
- Check: Next.js Server Actions without `await getSession()` before
  data operations
- Check: Supabase service role key accessible to user-facing code
  paths or MCP tools
- Check: a deploy or infrastructure-apply job whose only "approval" is
  a manual-dispatch toggle, or that binds a deployment environment with
  no required-reviewer protection rule configured server-side — the
  gate is present in the workflow file but inert, so a single actor
  ships to production unreviewed; verify the environment's protection
  rules via the platform API, not the YAML (for a reusable workflow the
  environment resolves against the calling repo)

For each finding not already in the path model, add:

```
**[STRIDE category]: [one-line description]**
Element:     [data flow element where this occurs]
Condition:   [what makes this exploitable]
Disposition: [mitigate / accept / defer / transfer]
```

---

## Phase 5: Shared dependencies and baseline integration

### 5A: Shared dependencies

Review all paths and STRIDE findings. For each "Breaks with" field
in the path model, note the control named. For STRIDE findings whose
Disposition is `mitigate`, the control is implied by the finding —
name it from what the mitigation would require (e.g., "Add signed
webhook validation"). Skip STRIDE findings with non-mitigate
dispositions. Count how many paths and findings each control appears
in.

Produce an ordered list from most paths blocked to fewest:

> "These controls break the most attack chains — prioritize in this
> order:
> 1. [Control] — blocks [Asset A] Path 1, [Asset B] Path 2, ...
> 2. [Control] — blocks [Asset A] Path 3, [Asset C] Path 1
> ..."

A control blocking 3 paths across 2 assets is higher value than one blocking 1.
This ordering is the direct answer to "where do I start?"

### 5B: Baseline integration

**If lint-baseline output is in session context** (from a prior run
this session or a `docs/lint-baseline-report.md` file):

For each control in the shared-dependency list, identify the
corresponding baseline item and show its actual verdict:
- "Egress allowlist → baseline item 8: **GAP** — lint-baseline found
  `requests.get(tool_input.url)` with no allowlist in tools/fetch.py"
- "Tenant-scoped queries → baseline item 1: **PASS**"
- "Trace redaction → baseline item 6: **UNKNOWN** — observability SDK
  detected in requirements but no init call found"

**If lint-baseline has not been run:**

For each control, name the relevant baseline item and note:
- "Egress allowlist → baseline item 8. Run lint-baseline to verify
  whether this gap exists in your codebase."

Do not fabricate verdicts. Use these exact labels:
- If lint-baseline ran and covered this item: use the actual verdict
  (PASS / GAP / UNKNOWN)
- If lint-baseline ran but this specific item is not in the report:
  use `UNKNOWN` with a note "(not in report)"
- If lint-baseline has not been run: use `not checked`

---

## Phase 6: Write docs/threat-model.md

After all five phases are complete, write the full document. Create
the `docs/` directory if it does not exist. For the document title,
use the git repository name if available (from `git remote get-url
origin` or `git rev-parse --show-toplevel`), otherwise use the
basename of the working directory. Write to `docs/threat-model.md`
using this structure exactly:

```markdown
# Threat model · [repo name or current directory] · [YYYY-MM-DD]

**Adversary assumption:** [commodity / sophisticated] — [one sentence
rationale, or the specific signal that flipped to sophisticated]

---

## Data flows and trust boundaries

**External entities:** [comma-separated list]

**Processes:** [comma-separated list]

**Data stores:** [comma-separated list]

**Trust boundaries:**
- [Boundary name]: [what crosses it] — [trust level change]
- ...

---

## Assets

| Asset | Description | Harm if compromised |
|-------|-------------|---------------------|
| [name] | [what it is] | [specific business harm] |

---

## Attack paths

### [Asset name]

**Path 1 — [name] (cheapest)**

| | |
|---|---|
| Initial access | [specific vector] |
| Required privileges | [what] |
| Lateral movement | [steps] |
| Detection opportunity | [specific signal] |
| Breaks with | [control] |
| Disposition | [decision] |

[Repeat table for Paths 2–N under the same asset]

### [Next asset name]

[Paths 1–N in same format, cheapest first]

---

## STRIDE findings

[Only findings not captured in path model]

**[Category]: [description]**
- Element: [data flow element]
- Condition: [what makes it exploitable]
- Disposition: [decision]

---

## Raise the floor here first

Controls ordered by attack chains blocked:

1. **[Control]** — breaks paths [list] · baseline item [N]: [PASS / GAP / UNKNOWN / not checked]
2. ...

---

## What this threat model does not do

- Assign probability estimates or dollar-value impact
- Map to compliance frameworks
- Attribute to specific threat actor groups
- Substitute for a red team engagement or pen test
```

After writing the file, tell the user:
> "Threat model written to `docs/threat-model.md`.
> [N] assets · [N] attack paths · [N] STRIDE findings
> Top priority: [first item from 'raise the floor' list]"
