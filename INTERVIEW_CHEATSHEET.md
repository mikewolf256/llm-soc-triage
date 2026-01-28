# Interview Cheat Sheet — Caribou HM

## 60-Second Positioning
I build AI-assisted detection pipelines that cut false positives and speed response without breaking compliance. My `llm-soc-triage` project is a production-ready middleware that normalizes alerts, scrubs PII locally, enriches with business context (RAG), and returns validated, SOAR-compatible output. I also build offensive tooling (`agentic-bugbounty`) to validate detections from the attacker’s perspective, so I can close the loop between red and blue.

## JD Match (Caribou Outcomes)
- AI-assisted triage automation → deterministic pipeline + strict schemas + guardrails
- Cut false positives via business context → RAG + ownership-aware detection logic
- Improve MTTD/MTTR → fast preprocessing + rule gating + selective LLM use
- SOC investigations + IR → structured outputs, SOAR-ready actions, audit trail
- Honest Security / compliance → local PII scrubbing + data residency controls

## Red + Blue Pivot (Use This Line)
I treat offense as validation for defense: I build red-team automation to find real attack paths, then encode those behaviors into high-confidence detection logic with strict privacy boundaries.

## Project Highlights (llm-soc-triage)
- **PII-safe LLM boundary**: Presidio + regex failover; send only scrubbed data out.
- **RAG context layer**: historical ticket similarity + business asset context.
- **Prompt injection defense**: XML delimiters around untrusted logs.
- **Strict output validation**: Pydantic schemas prevent hallucinated fields.
- **Ownership-aware IDOR detection**: correlates auth failures + telemetry + Redis state.
- **Chronicle integration**: webhook ingest, enrichment, case creation, UDM annotations.

## Project Highlights (agentic-bugbounty)
- **Autonomous recon & validation**: ZAP/Nuclei/Dalfox/sqlmap + LLM triage.
- **Noise reduction**: pre-filtering before LLM to cut costs and focus signal.
- **Evidence-first reporting**: structured JSON + Markdown reports.
- **Scalable execution**: containerized workflows and queue-ready design.

## 3 Concrete Talking Points
1) **False positive reduction**: ownership-aware detection + context reduces alert fatigue.
2) **Compliance-first AI**: scrub locally, validate outputs, keep sensitive data inside.
3) **Builder mindset**: I ship end-to-end pipelines, not just dashboards.

## 3 Questions for the HM
1) Where is your biggest triage bottleneck today (EDR, cloud, auth, web)?
2) How much business context is embedded in detections vs in analysts’ heads?
3) What’s your tolerance for auto-remediation vs human-in-the-loop?

## Quick Wins If Hired (First 90 Days)
- Baseline FP rate and build a context-enriched triage prototype.
- Add deterministic rule gates to reduce LLM calls and improve trust.
- Ship 1–2 high-signal detections with metrics and feedback loop.

## Links
- Caribou JD: https://job-boards.greenhouse.io/caribou/jobs/7584344003
- Project: `llm-soc-triage`
- Repo: https://github.com/mikewolf256/agentic-bugbounty
