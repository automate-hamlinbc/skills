---
name: security-persona
description: >
  Produces a factual security posture document (docs/security-posture.md)
  and engineering roadmap by reading the codebase and any prior skill
  output. Asks 3–5 code-adjacent questions for things the code cannot
  fully answer. Run after lint-baseline and threat-model for best results.
---

# security-persona v0

You are producing a factual security posture assessment of this codebase.
This document helps a CTO or senior engineer communicate security posture
to a sophisticated prospect or enterprise customer. It is honest and
evidence-tiered — it distinguishes what is verified in code, what is
user-stated, and what is not yet addressed.

This session writes `docs/security-posture.md`. Work through all three
phases before writing the document.

---

## Phase 1: Codebase and prior skill discovery

**Detect prior skill output first:**

Check for `docs/lint-baseline-report.md` or lint-baseline output in
session context. If present, extract the verdict (PASS / GAP / UNKNOWN)
for each of these items — match by heading or item name:
- Item 1: tenant-scoped DB queries (maps to Domain 1)
- Item 2: HTML sanitizer on LLM output (maps to Domain 3 — agent safety)
- Item 3: OAuth tokens and API keys in vault or env (maps to Domain 2)
- Item 4: typed messages with provenance tags (maps to Domain 3)
- Item 5: dangerouslySetInnerHTML / |safe / raw markdown (maps to Domain 3)
- Item 6: observability SDK redaction; tool returns no credentials (maps to Domains 2 and 4)
- Item 7: caches keyed by tenant_id (maps to Domain 1)
- Item 8: agent worker egress allowlist (maps to Domain 3)

Check for `docs/threat-model.md`. If present, extract:
- The adversary assumption (commodity / sophisticated)
- The "Raise the floor here first" ordered list — use this to order
  the roadmap in Phase 3

If prior skill output exists, scan for material code changes since it
ran: new LLM tool definitions, changes to auth middleware, new external
integrations, new admin route handlers. If any are found, note them and
re-run the relevant domain check rather than relying on the prior verdict.
Surface confirmed changes as a note in the output document under the
affected domain.

Now read the codebase across six domains (plus an optional Deployment
and supply chain companion, Domain 7, when the repo has CI/CD or IaC).
For each domain, build an internal evidence map: what is present (with
file references), what is absent, what is ambiguous. This drives the
Phase 2 questions and the output tiers.

### Domain 1: Data isolation

Read: model definitions (`models.py`, `schema.prisma`, Alembic
migrations, Prisma/Drizzle schema files), route handlers, query sites,
cache patterns.

- Tenant_id fields in model definitions — which models are
  tenant-scoped?
- RLS: search for `ENABLE ROW LEVEL SECURITY` in migrations or
  Supabase schema definitions. Present or absent?
- Query patterns: `.get(id)` or `.filter(id=id)` on tenant-scoped
  models without a tenant predicate vs. a scoped helper that enforces
  tenant context
- Cache key derivation: `SETEX cache:${hash(query)}` (no tenant
  prefix) vs. `cache:${tenant_id}:${hash(query)}`
- `createClient(url, SERVICE_ROLE_KEY)` in server actions (bypasses
  RLS entirely)

### Domain 2: Credential and secret handling

Read: ORM model definitions, environment variable references, vault
client imports, observability SDK initializations, tool return handlers.

- ORM column names containing `*_token`, `*_secret`, `*_key`,
  `*_api_key`, `*_password`, `refresh_token` — without encryption
  decorators
- Secret patterns: `os.getenv`, `process.env`, vault SDK imports
  (boto3 secretsmanager, doppler, hvac) vs. hardcoded key-shaped
  strings outside test files
- Observability redaction: Langfuse `mask=`, LangSmith
  `process_inputs`/`process_outputs`, Phoenix/Arize equivalent —
  present or absent at SDK initialization
- Tool return values: functions returning `response.text` or raw
  HTTP response bodies that may contain `Authorization` headers or
  API keys in URL parameters

### Domain 3: Agent safety

Read: LLM tool definitions, agent worker files, MCP server definitions,
context construction patterns.

- Egress controls: `ALLOWED_HOSTS`, `allowed_hosts`, allowlist
  constants adjacent to URL-accepting tool definitions. `url: str`
  with no constraint vs. typed/validated URL parameters
- Tools named `fetch_url`, `web_search`, `browse`, `http_request`,
  or `web_fetch` — do they have host validation adjacent to the
  definition?
- Context construction: f-string or `+` concatenation of trusted
  instructions with retrieved or user-supplied content vs. typed
  message objects with distinct sources. Also check: LangChain
  `PromptTemplate` with retriever-filled variables passed to the model
  without trust delimiters; Jinja2 templates rendering retrieved content
  into the system message; RAG context stuffed into the system message
  as raw text without provenance markers.
- MCP server tool definitions: tools accepting arbitrary URLs or
  running shell commands without constraints

### Domain 4: Observability

Read: observability SDK initialization files, logging patterns,
background task definitions, admin operation handlers.

- Langfuse, LangSmith, Phoenix, Helicone imports — do their init
  calls include redaction callbacks (`mask=`, `process_inputs`,
  `process_outputs`)? Absent callback = all prompts, tool inputs,
  and tool outputs stored in plaintext
- Structured logging or audit trail for admin operations: bulk
  mutations, exports, account deletions — present or absent?
- Agent tool calls: captured in observability traces or only in
  application logs?
- Background tasks: job history or audit records present?

### Domain 5: Auth surface

Read: route handlers, middleware, session management, admin routes,
Server Actions, Supabase client usage.

- Identity sourced from HTTP headers (`X-User-Id`, `X-Tenant-Id`,
  `X-Forwarded-For`) without session verification — means any
  caller can impersonate any user
- Admin route privilege checks: authentication only (anyone logged
  in can reach it), or explicit role check beyond authentication?
- Next.js Server Actions: `await getSession()` or equivalent before
  any data operation — or missing?
- Supabase service role key: accessible only in designated admin
  paths, or reachable from user-facing routes or MCP tools?
- JWT validation: `iss` and `aud` claims checked, or signature only?

### Domain 6: Attack surface posture

- If `docs/threat-model.md` exists: read the adversary assumption
  and the "Raise the floor here first" ordered list. Extract the top
  3 controls and the paths each blocks. Use this ordering in Phase 3
  roadmap as a secondary sort (after prospect-visibility).
- If threat-model has not been run: note this — the roadmap will
  lack structural path analysis. Recommend the user run
  threat-model after this skill for a more complete picture.

### Domain 7: Deployment and supply chain (companion)

Assess only when the repo has CI/CD workflows (`.github/workflows/*.yml`,
other pipeline definitions) or infrastructure-as-code; otherwise mark
N/A and say why. This is operational posture, not one of the six
application domains — keep it in its own section of the output and do
not blend it into the application verdicts.

Read: pipeline definitions, deployment jobs, the platform's
environment/approval settings, IaC templates.

- Deploy approval gate: does each deploy or infra-apply job require a
  real second-person approval? A manual-dispatch toggle alone, or a
  deployment environment with no required-reviewer protection rule, is
  an inert gate — verify protection rules via the platform API
  (`gh api repos/<owner>/<repo>/environments`), not the workflow file.
  For a reusable workflow the environment resolves against the calling
  repo, so check per-caller.
- Action / workflow pinning: are third-party actions on privileged
  jobs pinned to a full commit SHA rather than a movable tag? Do
  shared/reusable workflows pin their own actions and protect the
  consumed tag?
- Deploy credentials: short-lived federated credentials (OIDC) vs. a
  long-lived stored deploy token or service-principal secret — and
  does any unavoidable standing credential have a documented rotation
  owner?
- Shared-workflow integrity: a security or quality gate the caller can
  silently lower (for example, a coverage threshold overridable to
  zero) on a workflow consumed across many repos.
- Source-of-truth integrity: is the deployed revision reachable from
  the mainline branch, and does live infrastructure match the declared
  IaC? Deployed-but-unlanded code means a clean redeploy ships
  something else.

Where a control's enforcement lives in another repo (a reusable
workflow, or the caller's environment settings), record it as a
cross-boundary unknown with the flip-condition — what to check, and
where — never as verified from the visible side alone.

---

## Phase 2: Code-adjacent questions

Review your evidence map from Phase 1. Ask questions **only** for
domains where you found ambiguous or partial evidence — things the
code hints at but cannot fully answer. Maximum 5 questions.

Do not ask about incident response, access management policy, data
handling policy, vendor security, or penetration test history. These
are operational controls scaffolded in the output for the user to
complete independently.

Skip the adversary framing question if `docs/threat-model.md` already
exists.

**Generate questions from these patterns — use only where evidence
was ambiguous:**

- **Secrets management depth:** "I see secrets referenced via
  environment variables. Are these managed in a secrets manager
  (AWS Secrets Manager, Doppler, Vault) or set directly in deployment
  configuration?"

- **Prod/staging separation:** "I don't see explicit environment
  separation in the configs. Is there a separate production
  environment with restricted engineer access, or do engineers have
  direct production database access?"

- **Blast radius of engineer credential compromise:** "Given the
  service account permissions visible in the codebase — what is the
  blast radius if an engineer's credentials were compromised? Can a
  compromised engineer account reach all customer data?"

- **Tenant isolation confirmation:** "I see tenant_id patterns
  suggesting multi-tenancy. Is all customer data fully isolated per
  tenant, including caches and background job queues — or are there
  shared tables without tenant predicates?"

- **Adversary framing** (ask only if threat-model has not run):
  "Does any of the following apply to your product?
  - Large asset base or ARR making a targeted attack economically
    justified
  - Sensitive regulated data at scale: PHI, financial records,
    government data
  - Third-party access position: MSP, supply chain of high-value
    targets, or privileged access to many customer environments
  - Activist, dissident, or politically sensitive user base
  If yes to any, note which."

Present all questions in one message. Wait for the user's responses
before proceeding to Phase 3.

---

## Phase 3: Write docs/security-posture.md

After phases 1 and 2 are complete, write the document. Create the
`docs/` directory if it does not exist. For the document title, use
the git repository name if available (from `git remote get-url origin`
or `git rev-parse --show-toplevel`), otherwise use the basename of
the working directory.

Use these evidence tiers consistently throughout the document:
- **Verified** — code-backed; state the file evidence
- **Claimed** — user-stated in Phase 2; not code-verified
- **Not yet addressed** — honest gap; no qualification or softening

Write to `docs/security-posture.md` using this structure exactly:

```markdown
# Security posture · [repo name] · [YYYY-MM-DD]

**Adversary assumption:** [commodity / sophisticated] — [one-sentence
rationale, or "threat-model not run — run /threat-model to establish
this"]

---

## Verified controls

Code-backed. Each claim is supported by evidence in the codebase.

### Data isolation
[What the code shows. Include specific file references where the
evidence is concrete. Example: "Row-level security enabled on all
multi-tenant tables (confirmed in migrations/0012_enable_rls.sql).
Tenant-scoped queries route through get_or_404_for_tenant() helper
(app/db/helpers.py)."]

### Credential and secret handling
[What the code shows. Example: "No plaintext credential columns in
ORM models. Secrets accessed via os.getenv() throughout. Langfuse
initialized with mask= callback at app/observability.py:14."]

### Agent safety
[What the code shows. Example: "fetch_url tool definition includes
ALLOWED_HOSTS constant (tools/fetch.py:8). Context built from typed
message objects — no f-string concatenation of trusted and untrusted
content found."]

### Observability
[What the code shows.]

### Auth surface
[What the code shows.]

---

## Claimed controls

User-stated in this session. Not verified in code — confirm
independently if needed.

[List each positive claim from Phase 2 answers as a bullet. Example:
"- Secrets managed in AWS Secrets Manager (engineer-confirmed)."
"- Production environment isolated; engineers do not have direct
  production database access (engineer-confirmed)."]

[If no positive claims were made in Phase 2, write: "None stated
in this session."]

---

## Not yet addressed

These gaps exist in the current codebase.

[List each gap identified in Phase 1 as a bullet. State plainly.
Example:
"- No egress allowlist on agent worker — any successful prompt
  injection has an open exfiltration channel (tools/fetch.py)."
"- Langfuse initialized without redaction callback — all prompts,
  tool inputs, and tool outputs are stored in plaintext traces
  (app/observability.py:6)."]

[If no gaps were found, write: "No gaps identified in the domains
assessed. See 'What this document does not cover' below."]

---

## Operational controls

> Not assessed by this skill. Fill in the sections relevant to your
> situation.

**Incident response**
[Describe your incident response process — who is first point of
contact, what is the escalation path, what is your target response
time for a confirmed security incident.]

**Access management**
[Who has production access? How is it provisioned and revoked? Do
engineers have direct database access?]

**Data handling**
[What is your data retention policy? How do you handle deletion
requests? Who are your key subprocessors that process customer data?]

**Vendor security**
[What third-party services process customer data? What security
certifications do they hold?]

**Third-party security assessments**
[Have you had a penetration test, red team engagement, or bug bounty
program? If so, when and by whom?]

---

## Strengthen the story

Engineering actions ordered by what a sophisticated prospect is most
likely to ask about first. Each item names the control, states why
it matters to a prospect in one sentence, and references the relevant
baseline item and threat-model paths where applicable.

[For each gap from "Not yet addressed", produce one roadmap item.
If the "Raise the floor here first" list from threat-model is
available, use it as a secondary sort. Format:

1. **[Control to implement]** — [why this matters to a prospect in
   one sentence].
   Baseline item [N]: [PASS / GAP / not checked] · threat-model:
   [path references if available]

Example:
1. **Add egress allowlist on agent worker** — A prospect asking
   about data exfiltration controls will ask this directly; without
   it, any prompt injection has an open exfiltration channel.
   Baseline item 8: GAP · threat-model: [Asset] Paths 1, 2

2. **Add Langfuse redaction callback** — Plaintext trace stores are
   a common finding in vendor security reviews.
   Baseline item 6: GAP]

---

## What this document does not cover

- Operational controls (incident response, access management, data
  handling, vendor security) — see scaffolded sections above
- Penetration testing or adversarial verification of controls
- Compliance framework mapping (SOC 2, ISO 27001, NIST)
- Probability or impact quantification
- Code correctness beyond the six domains assessed
```

After writing the file, tell the user:
> "Security posture written to `docs/security-posture.md`.
> [N] verified controls · [N] gaps · [N] roadmap items
> Most pressing for a prospect review: [first roadmap item]"
