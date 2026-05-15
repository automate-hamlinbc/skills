---
name: lint-baseline
description: >
  Audits a repository against the Adversis v0 security baseline for
  agentic SaaS applications. Produces a pass/gap/unknown verdict per
  baseline item plus framework-specific findings for FastAPI, Next.js,
  Supabase, and MCP server integration patterns. Use when you want to
  check an agentic app codebase before a security review.
---

# lint-baseline v0

You are conducting a security audit of this codebase against the
Adversis v0 baseline. The baseline is defined at `docs/v0-baseline.md`
in this repo (or at adversis.io/baseline when published).

## Before you begin

Ask: **"One-shot report or interactive walkthrough?"**

- **One-shot**: run all checks, produce the full report, no questions
- **Interactive**: work item by item; ask one targeted question before
  issuing a verdict on items with behavioral components (2, 4, 7, 8);
  allow discussion before moving to the next item

Then proceed immediately to stack detection without waiting for further
input.

## Step 1: Stack detection

Read these files to identify which stack components are present:
- `package.json` and/or `package-lock.json`
- `requirements.txt`, `pyproject.toml`, or `uv.lock`
- `docker-compose.yml` and/or `Dockerfile`
- `.env.example` (if present)
- Directory structure: presence of `app/`, `src/`, `pages/`, `app/`
  (Next.js app dir)

Grep for these library patterns to confirm:
- FastAPI: `from fastapi` or `fastapi` in requirements
- SQLAlchemy: `sqlalchemy` in requirements
- Next.js: `"next"` in package.json dependencies
- Vercel AI SDK: `"ai"` in package.json dependencies
- Supabase: `"@supabase/supabase-js"` in package.json
- MCP servers: `mcp.json`, `.mcp.json`, `@modelcontextprotocol/sdk`,
  or `mcp` in requirements
- Langfuse: `langfuse` in requirements or package.json
- LangSmith: `langsmith` in requirements
- Arize Phoenix: `arize-phoenix` or `openinference` in requirements
- Helicone: `helicone` in package.json
- LangGraph: `langgraph` in requirements
- LangChain: `langchain` in requirements
- nginx: `nginx.conf` or `default.conf` present in repo

Record what you found. Only run checks relevant to the detected stack.
Skip any check for a stack component not present.

State your findings:
```
Stack detected:
  Backend:       [FastAPI / other / none]
  Database:      [PostgreSQL/Supabase / other / none]
  Frontend:      [Next.js / other / none]
  AI SDK:        [Vercel AI SDK / LangChain / LangGraph / other]
  MCP:           [yes / no]
  Observability: [Langfuse / LangSmith / Phoenix / Helicone / none]
  Proxy:         [nginx config present / not detected]
```

## Suppression rules — do not flag

Apply these rules during discovery (pass 1) before promoting a
candidate to validation. These represent patterns the framework
handles automatically.

**FastAPI / SQLAlchemy:**
- SQLAlchemy ORM queries (`.filter(`, `.filter_by(`, `.all()`,
  `.first()`) are not flagged for SQL injection unless `.execute(`
  with string interpolation, `text()` with unsafely bound params,
  or `.from_statement(` is used. Additionally flag `order_by()`,
  `group_by()`, or `literal_column()` called with a user-controlled
  string — these emit raw SQL and are injection vectors.
- `os.environ.get(`, `settings.X`, `config.X` values are
  server-controlled — do not flag as attacker-controlled inputs for
  SSRF or injection purposes.
- Test files (`tests/`, `conftest.py`, `*_test.py`, `test_*.py`)
  and fixture files are not in scope. Note them briefly as excluded.

**React / Next.js:**
- React JSX `{variable}` expressions are auto-escaped — do not flag
  for XSS unless `dangerouslySetInnerHTML` or `.innerHTML` is used.
- `process.env.NEXT_PUBLIC_*` values in client components: expected
  behavior. Flag only when the value matches a secret key pattern.
- `params`, `searchParams` in server components are not auto-sanitized
  but are also not auto-rendered — flag only when the value reaches
  a render primitive or DB query without validation.

**Supabase:**
- The Supabase anon key (starts with `eyJ`) and new publishable key
  (`sb_publishable_*`) are safe to expose client-side — not credential
  gaps. Flag the legacy service role JWT (role `service_role`) and new
  secret key (`sb_secret_*`).
- RLS is effective when tables have `ENABLE ROW LEVEL SECURITY` AND
  at least one policy. Flag absence of either.

**Committed test and example files:**
- Any secret-shaped string in a file path containing `test`, `fixture`,
  `example`, `mock`, `stub`, `seed`, `fake`, or `dummy` — note in
  the report as excluded, do not flag as a finding.
- `.env.example` files with clearly placeholder values (`REPLACE_ME`,
  `your-key-here`, `xxx`, `<your-key>`) — not a finding.

## Step 2: Baseline audit

**Before beginning**: Read `docs/lint-baseline-patterns.md`. The credential
patterns, non-credential patterns, deprecated library list, CVE findings,
and complementary tools table in that file are authoritative for Steps 2–5.
Use them in place of any inline data below.

Work through all 8 items. For each item:
1. **Discovery**: search for the patterns described. Cast wide — flag
   anything that could be a gap.
2. **Validation**: for each candidate, re-examine it with a skeptical
   framing. Can you trace a concrete path from a network entry point
   (route handler, RPC method, message queue consumer) to the gap in 5
   hops or fewer? If not, downgrade to OBSERVATION rather than GAP. If
   the path crosses an auth or tenant-scope check, note it.
3. **Issue verdict**: PASS / GAP / PASS · behavioral eval required /
   UNKNOWN.

In interactive mode: before issuing a verdict on items 2, 4, 7, 8, ask
one targeted clarifying question if deployment context would change the
verdict.

---

### Item 1: Tenant-scoped DB queries

**Patterns to search (discovery):**

FastAPI / SQLAlchemy:
- `session.get(ModelClass, ` — any call where `ModelClass` is a
  tenant-scoped model (has a `tenant_id` column) and no predicate
  follows
- `.filter_by(id=` or `.filter(ModelClass.id ==` without
  `tenant_id` in the same query
- `cursor.execute(` with string interpolation (not parameterized)
- Alembic migration files that `INSERT` or `UPDATE` tenant-scoped
  tables without setting `app.current_tenant`
- Celery tasks that query tenant-scoped models without a
  `SET LOCAL app.current_tenant` statement

Next.js / Supabase:
- `createClient` called with a variable that could be the service role
  key (grep for `SERVICE_ROLE`, `service_role`)
- Supabase queries using `.eq('id', id)` without `.eq('tenant_id', )`
  or without RLS confirmed enabled
- Check migrations: tables created without `ALTER TABLE ... ENABLE ROW
  LEVEL SECURITY` following the `CREATE TABLE`

**Validation for each candidate:**
Can you reach this query from an authenticated HTTP request without
providing the tenant ID from the session? If yes: GAP. If the query
is in a clearly admin-only file or behind an explicit admin guard:
OBSERVATION (note the file and the guard, flag if the guard looks weak).

**False positives:**
- Admin endpoints explicitly scoped to superuser/admin roles are not
  a gap for this item — note them and move on
- Test files and fixtures

**Verdict states for this item:**
- `PASS`: all tenant-scoped model queries provably scope by a
  session-derived tenant ID; RLS enabled on all multi-tenant tables
  in migrations; `service_role` key appears only in files flagged as
  admin-only
- `GAP`: found a query without tenant predicate reachable from a
  non-admin authenticated path
- `UNKNOWN`: cannot determine which models are tenant-scoped (unusual
  schema structure)

### Item 2: Sanitizer on every LLM-output render path

**Patterns to search (discovery):**

Next.js / React:
- Import of `react-markdown`, `marked`, `markdown-it`, `remark`, or
  `rehype` — note whether a sanitizer (`rehype-sanitize`, `DOMPurify`)
  is imported in the same file
- `dangerouslySetInnerHTML` applied to any variable that could be
  LLM output (variable names: `response`, `content`, `message`,
  `output`, `completion`, `text`, `result`)
- `<ReactMarkdown>` components without a `rehypePlugins` prop

Python / FastAPI / Jinja:
- `| safe` filter applied to a variable tracing to LLM output
- `Markup(` applied to a variable not from a known-safe source
- `markdown(` or `mistune.html(` without `bleach.clean(` in scope

MCP:
- Tool result strings passed directly to the host without sanitization

**Validation for each candidate:**
Is the variable receiving the unsafe treatment actually sourced from
LLM output (check the call stack — does it come from an `openai`,
`anthropic`, `ai`, or similar SDK call)? If yes and no sanitizer
is present: GAP.

In interactive mode: ask "Is markdown rendering of LLM responses
intentional? If yes, is there a documented CSP `img-src` allowlist?"
before issuing behavioral eval status.

**Verdict states for this item:**
- `PASS · behavioral eval required`: every path from model response to
  render passes through an active sanitizer (DOMPurify, rehype-sanitize,
  or current equivalent — check **Deprecated libraries** in
  `docs/lint-baseline-patterns.md` before accepting bleach as passing);
  no `dangerouslySetInnerHTML`, `|safe`, or `{@html}` applied to LLM
  output without an explicit sanitizer call upstream; reference-style
  markdown and CSP correctness require behavioral verification
- `GAP`: LLM output reaches a render primitive without a sanitizer
- `UNKNOWN`: cannot trace LLM output to render paths (complex
  component graph)

### Item 3: Secrets in vault or env — not database columns

**Patterns to search (discovery):**

ORM models (SQLAlchemy, Prisma, Drizzle, Django models):
- Column names matching `*_token`, `*_secret`, `*_api_key`,
  `*_access_key`, `*_refresh_token`, `*_private_key`
- Any `String` / `Text` column without an explicit encryption
  decorator or comment

Source files (all languages):
- Grep for each pattern in the **Credential-shaped patterns** table in
  `docs/lint-baseline-patterns.md`. Scope: all files not in `tests/`,
  `fixtures/`, `.env.example`, `README.md`.

Configuration files:
- `mcp.json`, `.mcp.json`, `claude_desktop_config.json` — check for
  hardcoded credential values (not env var references)

**Validation for each candidate:**
Is the column or variable actually storing credentials at runtime, or
is it a schema field that happens to be named `token`? Is the
credential shape in source a real value or a placeholder? Flag only
values that look live (not `REPLACE_ME`, `your-key-here`, `xxx`).

**False positives:**
- Test and fixture files (see suppression rules above)
- All patterns in the **Non-credential patterns** table in
  `docs/lint-baseline-patterns.md` — suppress these; do not flag

**Verdict states for this item:**
- `PASS`: no ORM column named `*_token`, `*_secret`, `*_key`, or
  `*_api_key` without an encryption decorator; no credential-shaped
  strings from `docs/lint-baseline-patterns.md` found in source outside
  test fixtures; credentials read from a secrets manager client or
  environment variable, not from a DB query result
- `GAP`: live credential found in source or DB column without
  encryption

### Item 4: Typed messages with provenance tags

**Patterns to search (discovery):**

Python / LangGraph / LangChain:
- f-string prompt construction that includes retrieval variables:
  `f"...{doc}..."`, `f"...{context}..."`, `f"...{retrieved}..."`,
  `f"...{result}..."`, `f"...{email}..."`, `f"...{ticket}..."`
- String concatenation building a prompt: `prompt = system + "\n" +
  user_input + "\n" + retrieved_text`
- `PromptTemplate` with variables that could be retriever-filled

Vercel AI SDK / TypeScript:
- `messages` array built by appending retrieval results to a
  `system` or `user` role without a trust delimiter
- `systemPrompt` variable that concatenates trusted instructions
  with untrusted content using template literals

LangChain specifically:
- `RetrievalQA`, `ConversationalRetrievalChain` — check whether
  retrieved documents are distinguished from user instructions; see
  **Deprecated libraries** in `docs/lint-baseline-patterns.md` for
  current status and recommended replacement

**Validation for each candidate:**
Is the concatenated variable actually sourced from an untrusted source
(retrieval, tool result, web content, user-uploaded file)? If it's
all from a single trusted source (pure user message + system
instruction with no retrieval), not a gap.

In interactive mode: ask "Is your retrieval source internal-only
(your own vector store with controlled content), or can it include
user-uploaded documents, email content, or web-fetched material?"
A fully internal-only source lowers the injection surface; user
uploads or web content make this item's PASS condition critical.

**Verdict states for this item:**
- `PASS · behavioral eval required`: LLM calls use typed message
  objects with distinct sources; no f-string or `+` concatenation
  of trusted instructions with retrieval results; untrusted content
  wrapped in unambiguous delimiters; behavioral verification
  (promptfoo indirect injection tests) required to confirm the model
  honors the separation under adversarial prompts
- `GAP`: f-string or concatenation mixing trusted instructions with
  retrieval results, with no provenance delimiter
- `UNKNOWN`: LLM call structure too abstracted to trace (wrapped in
  a framework or SDK not recognized)

### Item 5: All uses of `dangerouslySetInnerHTML`, `|safe`, and raw markdown renderers are documented and sanitizer-covered

**Patterns to search (discovery — grep the entire codebase):**

- `dangerouslySetInnerHTML` (React) — any usage
- `bypassSecurityTrustHtml` (Angular) — any usage
- `v-html=` (Vue) — any usage
- `{@html ` (Svelte) — any usage
- `| safe` (Jinja2/Django templates) — any usage
- `Markup(` (Python MarkupSafe) — any usage applied to a non-constant
- `mark_safe(` (Django) — any usage
- `markdown(`, `mistune.html(`, `markdown2.markdown(` (Python) —
  import without a sanitizer in the same file (check **Deprecated
  libraries** in `docs/lint-baseline-patterns.md` for current
  sanitizer status and migration recommendation)
- `.innerHTML =` (vanilla JS) — any dynamic assignment
- `insertAdjacentHTML(` (vanilla JS) — any dynamic usage
- `document.write(` — any usage
- `href=`, `src=`, `formAction=` (React props) — flag when value is
  user-controlled; JSX escaping does not protect against `javascript:`
  URI injection
- `allowDangerousHtml` (MDX or markdown renderers) — any usage

**Validation for each candidate:**
Is this in a path that could receive LLM output, user input, or any
other untrusted content now or in future? The bar is lower than other
items — if the primitive exists without a sanitizer, it's worth
flagging even if the current value is trusted, because the primitive
becomes the hazard when the input changes.

**False positives:**
- Known-safe constant strings (`dangerouslySetInnerHTML={{ __html: '<br/>' }}`)
- Documented and audited allowlist entries with explicit comments

**Verdict states for this item:**
- `PASS`: no forbidden primitives, or all occurrences are in an
  audited allowlist with explicit justification
- `GAP`: forbidden primitive found without sanitizer and without
  documented justification

### Item 6: Trace redaction

**Patterns to search (discovery):**

Observability SDK initialization (check only SDKs detected in stack):
- Langfuse: `Langfuse(` or `CallbackHandler(` without a `mask=`
  parameter
- LangSmith: `Client(` without `hide_inputs=` / `hide_outputs=`
  parameters; or `@traceable` without `process_inputs=` /
  `process_outputs=` parameters (these are separate APIs: Client-level
  vs. function-level masking)
- Arize Phoenix: `px.launch_app(` or `OpenAIInstrumentor(` without
  a span processor that filters credential-shaped attributes
- Helicone: SDK init without a custom logger that redacts sensitive keys
- W&B Weave: `weave.init(` without attribute filtering

Tool function returns:
- Functions named `*_tool`, decorated with `@tool`, or in a `tools/`
  directory that call external APIs — do they return `response.text`
  or `response.headers` or the raw response object directly?
- Error handlers in tools that include the full exception (which may
  contain a URL with an API key in query params)

**Validation for each candidate:**
Is the observability SDK actually used in this codebase (did stack
detection confirm it)? Is the tool return actually reaching the trace
store, or is it handled elsewhere?

**Verdict states for this item:**
- `PASS`: every detected observability SDK initialization includes
  a redaction callback; tool result handlers strip credential-shaped
  patterns before returning; no function named `*_token` or `*_secret`
  returns its full input in error messages
- `GAP`: observability SDK initialized without redaction
- `UNKNOWN`: observability SDK detected in requirements but no init
  call found in source (may be initialized in a config not in the
  repo)

### Item 7: Caches keyed by (tenant_id, …)

**Patterns to search (discovery):**

Python:
- `@lru_cache`, `@cache`, `@cached`, `@cachetools.cached` —
  what is the key function? Does it include `tenant_id` or `user_id`?
- `redis.set(`, `redis.setex(`, `r.set(` — what is the key string?
  Does it include a tenant or user identifier?
- `cache.set(key, ` — same check

Next.js:
- `unstable_cache(` — is the cache key function or tag array including
  a user/tenant identifier?
- `React.cache(` — same check

Semantic cache libraries:
- Import of `gptcache`, or vector store used as a cache (Pinecone,
  Weaviate, Qdrant with a similarity lookup) — is there a documented
  per-tenant namespace?

In interactive mode: ask "Do you use semantic caching for LLM
responses? If yes, which library and how is the namespace scoped?"

**Validation for each candidate:**
Is the cached value tenant-specific (i.e., different tenants should
get different responses for the same query)? If the value is
genuinely tenant-agnostic (e.g., a public lookup table, today's
weather), no issue. If the value could differ by tenant, a key
without tenant_id is a gap.

**Verdict states for this item:**
- `PASS · behavioral eval required`: cache key derivation in all cache
  decorator usages includes a tenant or user identifier; no semantic
  cache library import without a documented per-tenant namespace
  strategy; adversarial collision testing required to fully verify
- `GAP`: cache key derivation omits tenant/user identifier on a
  tenant-specific value
- `UNKNOWN`: caching detected but key construction not traceable
  from source

### Item 8: Egress allowlist on the agent worker

**Patterns to search (discovery):**

Tool definitions:
- Functions decorated with `@tool` or in a `tools/` directory that
  accept a `url` or `uri` parameter — is the parameter typed as bare
  `str` or is it validated against an allowlist?
- `requests.get(url`, `httpx.get(url`, `fetch(url` — where is `url`
  defined? Is it model-produced or from a constrained source?
- Tools named `fetch_url`, `web_search`, `browse`, `http_request`,
  `get_url`, `visit_page` — is there an `ALLOWED_HOSTS` or
  `ALLOWED_DOMAINS` constant adjacent?

LangChain tools:
- `RequestsGetTool(`, `RequestsPostTool(` — is `allowed_hosts`
  parameter set?

MCP server tool definitions:
- Tools with URL parameters — is there a host allowlist enforced?

Image rendering (client-side):
- Note that client-side `<img>` rendering is itself an egress channel
  — item 8 and item 2 are co-dependent; passing one without the other
  does not block exfiltration

In interactive mode: ask "Is there a network-level egress allowlist
on the agent worker (VPC, firewall, Kubernetes NetworkPolicy)? This
is the structural enforcement that static analysis cannot verify."

**Validation for each candidate:**
Is the URL actually model-produced, or is it from a server-controlled
config? A `requests.get(settings.WEBHOOK_URL)` is not an egress issue
(server-controlled). A `requests.get(tool_input.url)` with no allowlist
is a gap.

**Verdict states for this item:**
- `PASS · behavioral eval required`: URL-parameter tool definitions
  use typed/validated parameters or an adjacent allowlist constant
  rather than `url: str` with no constraint; tools named `fetch_url`,
  `web_search`, `browse`, or `http_request` have an explicit
  `ALLOWED_HOSTS` constant; LangChain `RequestsGetTool` or equivalent
  includes `allowed_hosts`; note that application-level allowlists
  are not sufficient — network-level enforcement requires a runtime
  probe to verify
- `GAP`: URL-parameter tool found with no allowlist

## Step 3: Produce the baseline report

After all 8 items are complete, output the report in this exact
structure:

```
lint-baseline v0 · [repo name or current directory]
Stack detected: [list detected components]

── Baseline ─────────────────────────────────────────────────────
 1  Tenant-scoped DB queries           [verdict]
 2  Sanitizer on LLM output           [verdict]
 3  Secrets in vault/env              [verdict]
 4  Typed provenance context          [verdict]
 5  No forbidden render primitives    [verdict]
 6  Trace redaction                   [verdict]
 7  Tenant-keyed caches               [verdict]
 8  Egress allowlist                  [verdict]
─────────────────────────────────────────────────────────────────
```

Then for each item that is not a clean PASS, provide a detail block:

```
### Item N: [name]
**[VERDICT]**

Found: [specific file:line and the pattern]
Why it fails: [one sentence tracing to the pass criterion]
Remediation: [one concrete action — the minimum change to clear this item]
[For behavioral eval required items:]
Next step: Run [promptfoo / garak / egress probe] — see docs/v0-baseline.md
  for the specific test to run.
```

For items with a clean PASS, no detail block needed — the summary
line is sufficient.

After the baseline report, continue to Step 4 (framework depth layer).
The framework findings appear in a separate section after the baseline
summary — they are additional observations, not baseline verdict items.

## Step 4: Framework depth layer

Run this after the 8-item baseline is complete. These checks produce
a "Framework findings" section in the report. They are not rated
against the baseline criteria — they are stack-specific observations.

Issue each finding as:
- `FINDING` — confirmed gap with a traceable path
- `OBSERVATION` — pattern worth examining; reachability or intent
  unclear without context

---

### 4A. Choke point and middleware audit

The question for every security-critical decision: is it made in one
centralized place (making the secure path the default), or scattered
per-route/per-query/per-render (making every new code that forgets
it a silent gap)?

**Authentication centralization:**

FastAPI:
- Read the main app file and all router files. Is there a dependency
  (`Depends(get_current_user)` or equivalent) applied at the
  router-prefix level, or is it applied per-endpoint?
- If per-endpoint: count how many endpoints have it. If any route
  handler in a file that handles user data lacks it, flag as FINDING.
- Any route that reads `request.headers.get("X-User-Id")` or
  `request.headers.get("X-Tenant-Id")` and uses it for an auth or
  scoping decision without verifying it against a session: FINDING.
  Header values from clients are attacker-controlled.

Next.js:
- Read `middleware.ts` or `middleware.js`. What does the `matcher`
  pattern cover? List the route prefixes it DOES NOT cover.
- Flag any Server Action that does not call `await getSession()` or
  `await auth()` (or the project's equivalent) within the first 5
  lines: FINDING. Middleware does not protect Server Actions.
- Any server component or route handler that reads
  `headers().get('x-user-id')` or equivalent for auth: FINDING.

**CVE checks (only for detected stack components):**
Check `package.json` version values against the **CVE findings** table in
`docs/lint-baseline-patterns.md`. Apply the FINDING / OBSERVATION verdicts
defined there for each CVE entry.

**Tenant scope source:**
- Search for `tenant_id` appearing in query parameter extraction:
  `request.query_params.get("tenant_id")`, `params.tenant_id`,
  `searchParams.get("tenant_id")`, `req.body.tenant_id`.
- If tenant_id for a DB query comes from the request body or query
  params rather than from the session/JWT: FINDING (IDOR via trusted
  input — passing the wrong tenant_id bypasses the tenant scope even
  when the helper is used).

**Input validation placement:**

FastAPI:
- Route handlers that accept `body: dict` or `body: Any` instead of
  a typed Pydantic model: OBSERVATION (no schema enforcement at entry).
- Handlers that call `request.json()` directly and then pass the
  result to a DB operation: FINDING.

Next.js / Vercel AI SDK:
- `streamText(`, `generateText(`, `generateObject(` calls where tool
  `execute` functions receive parameters but no Zod schema is applied
  to the tool definition: OBSERVATION.

**Output encoding centralization:**
- If `rehype-sanitize`, `DOMPurify`, or `bleach` appears in more than
  2 distinct files without a shared wrapper function: OBSERVATION
  (each call site is an independent decision; future sites may omit
  the sanitizer).
- Identify whether there is one canonical "render LLM output" component
  or helper. If multiple: list them and confirm each is sanitized.

---

### 4B. LLM blind spot coverage

These are vulnerability classes where AI-assisted review is documented
to underperform. Apply explicit directed checks.

**IDOR / BOLA across tenant boundary:**
For every route handler or server action that accepts an object ID
(UUID, integer, slug) as a path or body parameter:
1. Find the DB query that retrieves the object.
2. Check whether the query includes a tenant or user predicate from
   the session — not from the request.
3. If the query fetches by ID alone: FINDING.
   Format: "Route `[METHOD] [path]` fetches `[Model]` by id without
   tenant predicate (file:line). Authenticated attacker can access
   any [Model] by guessing or enumerating IDs."

**Auth checks present but bypassable:**

Next.js middleware matcher gaps:
- From the `matcher` pattern in middleware.ts, list at minimum:
  `/api/` routes, `/admin/` routes, and any route prefixes in the
  app directory not covered by the matcher.
- If any of these handle user data or mutations: FINDING.

Conditional bypass in auth logic:
- Search for `if not settings.PROD`, `if os.environ.get("ENV") != "production"`,
  `if process.env.NODE_ENV === 'development'` inside auth functions
  or decorators: FINDING (auth bypass in non-prod; often reaches staging).
- `@csrf_exempt` on any POST endpoint that handles user data: FINDING
  (Django).

**Read vs. write permission disparity:**
- For any resource type (model, entity) with both GET and POST/PUT/
  DELETE handlers: confirm the ownership or tenant check is present
  AND equivalent in both. A `get_post(id, user_id=current_user.id)`
  that has a matching write path using only `id` is IDOR-on-write.
- This is most common in REST APIs where GET uses a queryset filter
  but POST/PUT accepts an ID in the body.

**Header trust:**
Search for these patterns and flag each as FINDING:
- `request.headers.get("X-Forwarded-For")` used for rate-limit,
  geo-restriction, or IP allowlist (attacker can spoof this header
  unless nginx is configured to overwrite it)
- `request.headers.get("X-Real-IP")` used for security decisions
- Any `X-User-*`, `X-Tenant-*`, `X-Role-*`, `X-Admin-*` header
  read for authorization without session verification
- `headers().get(` in Next.js server components used for auth scoping

**Implicit trust in internal calls:**
- Background tasks (Celery, BullMQ, FastAPI `BackgroundTasks`) that
  accept a `user_id` or `tenant_id` as a parameter and perform
  privileged operations: OBSERVATION (confirm the caller validates
  before passing).
- Service-to-service HTTP calls that pass `X-User-Id` or
  `X-Tenant-Id` headers without signing: OBSERVATION (internal
  network trust assumption; flag if the service is exposed externally).

---

### 4C. Stack-specific integration patterns

**nginx + app server path normalization (only if nginx config detected):**

Read all nginx `.conf` files in the repo. Check:
1. Does any `location` block use `proxy_pass` with a trailing slash
   (e.g., `proxy_pass http://backend/`)? If yes: note that nginx
   rewrites the location prefix — the app will see a different path
   than the nginx location matcher. Flag if the app has auth or routing
   logic based on path prefixes: OBSERVATION.
2. Is `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for`
   used (append, not overwrite)? If the app uses X-Forwarded-For for
   security decisions, this is controllable: FINDING.
   The safe form is `proxy_set_header X-Forwarded-For $remote_addr`.
3. Is `merge_slashes on` (nginx default) or `merge_slashes off`? If
   the app has auth middleware that matches on `/admin/` but nginx
   normalizes `//admin/` to `/admin/`, double-slash bypass is
   possible if the app re-processes the path before middleware runs:
   OBSERVATION.

**Next.js Server Actions (only if Next.js detected):**

1. Find all Server Actions (functions with `"use server"` directive
   at the top, or files with `"use server"` at the file level).
2. For each mutation Server Action (one that writes to DB, sends email,
   transfers data): confirm `await getSession()` or equivalent auth
   check appears before any data operation.
3. For each Server Action that accepts user input: confirm a Zod
   schema validates the input before it's used.
4. Server Actions that call Supabase with the service role key:
   confirm the call site is admin-only. If reachable from a
   user-facing component tree: FINDING.

**Vercel AI SDK tool definitions (only if Vercel AI SDK detected):**

1. Find all `tool(` or `tools: {` definitions.
2. For each tool with an `execute` function:
   - Is there a Zod schema via `parameters` (AI SDK ≤4) or `inputSchema`
     (AI SDK 5)? If neither: OBSERVATION.
   - Does the execute function call an external service? If yes, does
     it validate that the parameters match an allowlist before
     dispatching? If not and a URL parameter is involved: FINDING.
   - Does the tool return data that includes credentials, internal
     endpoints, or PII? If yes, is there a redaction step before the
     result re-enters the model context? If not: FINDING (also
     triggers baseline item 6).

**Supabase client context (only if Supabase detected):**

Grep for all `createClient(` calls. For each:
1. What is the second argument (the key)?
   - `process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY` in a client
     component: expected, fine.
   - `process.env.SUPABASE_SERVICE_ROLE_KEY` anywhere: flag unless
     the call site is demonstrably server-only AND admin-only. Check:
     is this file a Server Action, API route, or server component with
     no client-accessible path? If uncertain: FINDING.
   - `process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY`: FINDING
     (service role key in a public env var — exposed to every browser).
2. MCP tools that initialize a Supabase client: what key are they
   using? Service role + MCP tool + agent = RLS bypass on any
   injection: FINDING.

---

### Framework findings output format

After completing sections 4A, 4B, and 4C, output:

```
── Framework findings ────────────────────────────────────────────
[FINDING]      [one-line description]
[FINDING]      [one-line description]
[OBSERVATION]  [one-line description]
─────────────────────────────────────────────────────────────────
```

Then for each FINDING, provide a detail block:

```
**FINDING: [description]**
File: [path:line]
What it means: [one sentence — what an attacker gains]
Fix: [one concrete change]
```

For OBSERVATIONs, a single line in the summary is sufficient unless
you have a specific question to ask in interactive mode.

If no framework findings: output "── Framework findings: none ──".

## Step 5: What this didn't cover

At the end of every report, output this section. Use the **Complementary tools**
table in `docs/lint-baseline-patterns.md` for correct tool names, attributions,
and invocations. Include only rows where "When to include" matches the detected
stack.

```
This didn't cover the following
────────────────────────────────────────────
lint-baseline audits the 8 agentic-app baseline items plus
framework-specific patterns for the detected stack. It does not
replace a general security review or a full appsec engagement.

Complementary tools worth running:

[list tools from docs/lint-baseline-patterns.md — Complementary tools section —
 filtered by detected stack]
```
