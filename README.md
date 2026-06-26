# Adversis Security Skills

Security skills for agentic SaaS applications. Audit your codebase against a structured baseline, build a structural threat model, and produce a factual security posture document for prospect and customer reviews — all from Claude Code.

**Stack coverage:** FastAPI + PostgreSQL, Next.js + Vercel AI SDK + Supabase, LangChain, LangGraph, MCP servers.

## Install

### From GitHub

```bash
claude plugin marketplace add adversis/skills
claude plugin install adversis-security
```

Restart Claude Code after installation.

**Update:**

```bash
claude plugin marketplace update
claude plugin update adversis-security
```

Or run `/plugin` to open the plugin manager.

### Locally (from a cloned copy)

```bash
claude plugin marketplace add /path/to/skills
claude plugin install adversis-security
```

For example, if you cloned this repo to `~/adversis-skills`:

```bash
git clone https://github.com/adversis/skills ~/adversis-skills
claude plugin marketplace add ~/adversis-skills
claude plugin install adversis-security
```

## Get started

```
/security
```

`/security` asks what you are trying to do and routes you to the right skill. Start here if you are new to the plugin.

---

## Skills

| Skill | Command | Produces |
|-------|---------|----------|
| [Security](skills/security/SKILL.md) | `/security` | Routes you to the right skill |
| [Lint baseline](skills/lint-baseline/SKILL.md) | `/lint-baseline` | `docs/lint-baseline-report.md` |
| [Threat model](skills/threat-model/SKILL.md) | `/threat-model` | `docs/threat-model.md` |
| [Security persona](skills/security-persona/SKILL.md) | `/security-persona` | `docs/security-posture.md` |

### Natural run order

Each skill works standalone. Each is enriched by the prior one's output.

```
/lint-baseline  →  /threat-model  →  /security-persona
```

**`/lint-baseline`** reads your codebase and audits 8 ship-blocking security items against the [v0 baseline](docs/v0-baseline.md). Produces `docs/lint-baseline-report.md` with PASS/GAP/UNKNOWN verdicts per item and framework-specific findings. Takes 5–10 minutes.

**`/threat-model`** guides a structured threat model — asset discovery, data flow mapping, attack path modeling, and a full STRIDE sweep. Always interactive; plan 30–60 minutes. Produces `docs/threat-model.md` with attack paths ordered by structural impact, shared dependency table, and hardening priorities. Uses lint-baseline output when available. When the repo has CI/CD or IaC, the STRIDE sweep adds optional deployment and supply-chain checks (inert approval gates, unpinned shared workflows, forwarded-identity headers).

**`/security-persona`** reads the codebase and any prior skill output, then asks 3–5 targeted code-adjacent questions. Produces `docs/security-posture.md` — a factual, evidence-tiered posture document (verified / claimed / not yet addressed) with an engineering roadmap ordered by what a sophisticated prospect is most likely to ask first. Works standalone but is richest after both prior skills have run. When CI/CD or IaC is present, it adds an optional **Deployment and supply chain** companion domain, kept separate from the six application-layer verdicts.

---

## Reference docs

| Doc | Used by | Purpose |
|-----|---------|---------|
| [docs/v0-baseline.md](docs/v0-baseline.md) | `/lint-baseline` | The 8 baseline items: what each covers, what passing looks like, which items require behavioral verification |
| [docs/lint-baseline-patterns.md](docs/lint-baseline-patterns.md) | `/lint-baseline` | Credential patterns, non-credential suppressions, deprecated library flags, CVE findings, and complementary tool references — read at audit time |

---

## What the baseline covers

Eight items exploitable, fixable in a sprint, and visible to anyone who looks:

1. Tenant DB queries route through a scoped helper — not raw `.get(id)` on tenant-scoped models
2. An HTML sanitizer runs on every path that renders LLM output as markdown or HTML
3. OAuth tokens and API keys live in vault or env — not database columns
4. Agent context is built from typed messages with provenance tags — not flat-string concatenation
5. All uses of `dangerouslySetInnerHTML`, `|safe`, and raw markdown renderers are documented and sanitizer-covered
6. Observability SDKs are initialized with redaction; tool returns do not contain credentials
7. Caches are keyed by `(tenant_id, …)` — not query content alone
8. The agent worker has an egress allowlist; no untyped `fetch_url` or open-web tools without confirmation

Items 1, 3, 5, and 6 are fully static-catchable. Items 2, 4, 7, and 8 include behavioral components that require adversarial verification. See [docs/v0-baseline.md](docs/v0-baseline.md) for the full definition of each item.

---

## Repository structure

```
adversis/skills/
├── .claude-plugin/
│   └── plugin.json
├── skills/
│   ├── security/
│   │   └── SKILL.md          ← discovery entry point (/security)
│   ├── lint-baseline/
│   │   └── SKILL.md          ← codebase audit (/lint-baseline)
│   ├── threat-model/
│   │   └── SKILL.md          ← structural threat model (/threat-model)
│   └── security-persona/
│       └── SKILL.md          ← posture document (/security-persona)
├── docs/
│   ├── v0-baseline.md        ← baseline item definitions
│   └── lint-baseline-patterns.md  ← credential patterns + CVE data
└── README.md
```

---

## Contributing

Skills follow the [Agent Skills specification](https://agentskills.io/specification). Each skill requires a `SKILL.md` with YAML frontmatter:

```yaml
---
name: skill-name
description: >
  What this skill does and when to use it. Include keywords that help
  agents identify when the skill is relevant.
---
```

**Updating credential patterns or CVE findings:** edit `docs/lint-baseline-patterns.md` — the lint-baseline skill reads it at audit time. You do not need to touch `skills/lint-baseline/SKILL.md` for data-only updates.

**Updating the baseline items:** edit `docs/v0-baseline.md` and reflect any structural changes in the audit logic in `skills/lint-baseline/SKILL.md`.

**Adding a new skill:** create `skills/<name>/SKILL.md`, add an entry to the skills table in this README, and update the `/security` discovery skill routing if the new skill belongs in the main entry-point menu.

### Local development

See the [Install — Locally](#locally-from-a-cloned-copy) section above.

---

## What this plugin does not include

- SessionStart hook or automatic context injection — all skills are on-demand
- CI/CD integration or scheduled scanning
- Compliance framework mapping (SOC 2, ISO 27001, NIST)
- Dependency CVE scanning or software composition analysis (SCA)
- Penetration testing or adversarial verification

---

## License

MIT
