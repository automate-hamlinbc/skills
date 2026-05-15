---
name: security
description: >
  Entry point for the Adversis security plugin. Asks what you are
  trying to accomplish and routes you to the right skill:
  lint-baseline, threat-model, or security-persona. Start here.
---

# security

Ask the user:

> "What are you trying to do?
> 1. Audit an existing codebase against known security gaps
> 2. Build a structural threat model of the system
> 3. Prepare a security posture document for a prospect or customer
>    review
> 4. Not sure — help me pick"

Wait for the user's answer. Then respond as follows.

---

**If option 1 — audit existing codebase:**

> "Run `/lint-baseline`. It reads your codebase and audits against 8
> ship-blocking security items, producing
> `docs/lint-baseline-report.md` with PASS/GAP verdicts and
> file-level citations. Takes 5–10 minutes.
>
> After that, run `/threat-model` to model structural attack paths
> using what the audit found."

---

**If option 2 — threat model:**

> "Run `/threat-model`. It guides you through a structured threat
> model of your agentic codebase — asset discovery, data flow
> mapping, attack paths, and a STRIDE sweep — producing
> `docs/threat-model.md`. Always interactive; plan for 30–60
> minutes.
>
> Run `/lint-baseline` first if you haven't — the threat model uses
> its output."

---

**If option 3 — security posture for prospect or customer review:**

> "Run `/security-persona`. It reads your codebase and any prior
> skill output, asks 3–5 targeted questions, and produces
> `docs/security-posture.md` — a factual, evidence-tiered posture
> document with an engineering roadmap.
>
> Run `/lint-baseline` and `/threat-model` first for the richest
> output, but it works standalone."

---

**If option 4 — not sure:**

Ask:

> "Are you working on an existing codebase or starting fresh?"

- If **existing codebase**: respond with the option 1 text above
- If **greenfield / starting fresh**: respond with the option 2
  text above
