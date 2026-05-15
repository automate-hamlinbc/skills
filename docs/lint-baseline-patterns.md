# lint-baseline patterns reference

Read by the `lint-baseline` skill at the start of Step 2. Update this file to revise
credential patterns, deprecated library flags, CVE findings, and tool references
without modifying skill logic in `skills/lint-baseline/SKILL.md`.

Last updated: 2026-05-15

---

## Credential-shaped patterns

Flag any of these as a finding in Item 3. Grep scope: all source files excluding
`tests/`, `fixtures/`, `.env.example`, `README.md`, and any path containing
`test`, `fixture`, `example`, `mock`, `stub`, `seed`, `fake`, or `dummy`.

| Platform | Pattern | Notes |
|---|---|---|
| AWS long-term | `AKIA[0-9A-Z]{16}` | IAM user access key |
| AWS STS temporary | `ASIA[A-Z0-7]{16}` | Short-lived credentials; often equally damaging if the session is fresh |
| Stripe live secret | `sk_live_` | |
| Stripe restricted | `rk_live_` | Scoped but still a credential |
| GitHub PAT (classic) | `ghp_` | |
| GitHub OAuth user-to-server | `gho_` | |
| GitHub App user-to-server | `ghu_` | |
| GitHub App server / Actions | `ghs_` | Most commonly leaked in CI artifacts as `GITHUB_TOKEN` |
| GitHub refresh token | `ghr_` | |
| GitHub fine-grained PAT | `github_pat_` | Format: `github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}` |
| OpenAI legacy | `sk-[a-zA-Z0-9]{48}` | Legacy user keys; pattern still valid |
| OpenAI project key | `sk-proj-` | Default format since mid-2024 |
| OpenAI service account | `sk-svcacct-` | For automation/CI |
| OpenAI user (no project) | `sk-None-` | |
| Anthropic | `sk-ant-` | Matches all generations including `sk-ant-api03-` |
| Supabase secret key | `sb_secret_` | Replaces legacy `service_role` JWT in projects created after Nov 2025; Supabase auto-revokes on GitHub secret scanning detection |

---

## Non-credential patterns (suppress — do not flag)

| Pattern | Reason |
|---|---|
| Stripe `pk_live_` / `pk_test_` | Publishable keys; designed for client-side use |
| Stripe `sk_test_` | Test mode only; not a live credential |
| Supabase anon JWT (starts `eyJ`, role `anon`) | Safe to expose client-side by design |
| Supabase publishable key (`sb_publishable_*`) | New-format anon key (GA June 2025); safe to expose |
| Placeholder values: `REPLACE_ME`, `your-key-here`, `xxx`, `<your-key>` | Clearly not live |
| Any path containing `test`, `fixture`, `example`, `mock`, `stub`, `seed`, `fake`, `dummy` | Out of scope |

---

## Deprecated libraries

These patterns still match real security findings for their respective baseline items.
Flag the issue and include a migration recommendation in the finding text.

| Library | Deprecated | Replacement | Baseline item(s) | Notes |
|---|---|---|---|---|
| `bleach` | January 2023 (v6.0.0) | `nh3` | 2, 5 | Python HTML sanitizer; depends on unmaintained `html5lib`; maintainer has stated it will not be transferred; still issues minimal security releases |
| `langchain.chains.RetrievalQA` | LangChain 0.1.x (early 2024) | `create_retrieval_chain` (LCEL) | 4 | Still present in older codebases; emits `LangChainDeprecationWarning`; flag the injection surface and note the deprecation |
| `langchain.chains.ConversationalRetrievalChain` | LangChain 0.1.x (early 2024) | `RunnableWithMessageHistory` + LangGraph | 4 | Same as above |

---

## CVE findings

Check during Step 4 (framework depth layer) against the relevant detected stack.

### CVE-2025-29927 — Next.js middleware bypass

- **CVSS:** 9.1 (Critical)
- **Disclosed:** 2025-03-21
- **Stack:** Next.js, self-hosted only (`next start` or `output: standalone`). Vercel-hosted apps were protected at the platform edge.
- **Affected versions:** `>= 11.1.4` and any of:
  - `< 12.3.5`
  - `>= 13.0.0 < 13.5.9`
  - `>= 14.0.0 < 14.2.25`
  - `>= 15.0.0 < 15.2.3`
- **Fixed in:** 12.3.5 / 13.5.9 / 14.2.25 / 15.2.3
- **What it does:** An attacker sets the `x-middleware-subrequest` header with a crafted value and Next.js skips middleware execution entirely — bypassing authentication, authorization, CSP headers, and any other middleware-layer controls.
- **Check:** Read `package.json`. If the `next` version is in the affected range: FINDING.
- **Also check:** Does any nginx or reverse proxy config strip `x-middleware-subrequest` before the request reaches the app? If not: OBSERVATION (defense-in-depth gap; recommend stripping at the proxy even on patched versions).

---

## Complementary tools (Step 5)

Include only the rows where "When to include" matches the detected stack.

| Tool | Attribution | Invocation | When to include |
|---|---|---|---|
| security-review | Claude Code built-in | `/security-review` | Always |
| insecure-defaults | Trail of Bits | `/plugin install insecure-defaults` | Always |
| static-analysis | Trail of Bits | `/plugin install trailofbits/skills/plugins/static-analysis` | Always |
| zizmor | William Woodruff; sponsored by Trail of Bits and Grafana Labs; free | `cargo install zizmor && zizmor .` (or `uvx zizmor .`) | Only if `.github/workflows/` detected |
| mcp-scan | Snyk (formerly Invariant Labs); free | `uvx mcp-scan@latest .` | Only if MCP servers detected |
