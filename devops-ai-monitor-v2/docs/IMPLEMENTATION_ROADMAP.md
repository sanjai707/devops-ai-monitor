# Implementation Roadmap Status

| Phase | Status | Notes |
|---|---|---|
| 0 Repository audit | Verified | Architecture, data/API inventory, baseline services and tests documented |
| 1 Monitoring foundation | Verified | Docker polling, event collection, reconnection and observable status verified |
| 2 Historical metrics | Tested / Verified | SQLite samples, throughput rates, retention, summary and history API verified |
| 3 Incident management | Tested / Verified | Lifecycle states, audit history, comments, occurrence counts and API validation verified |
| 4 Evidence investigation | Tested / Verified | Evidence inventory, timeline, strict validation, low-confidence exit-137 handling verified |
| 5 Knowledge/memory | Tested / Verified | Approved-only SQLite retrieval, version history and Knowledge Center verified |
| 6 Feedback | Tested / Verified | Feedback persistence, analytics, review workflow and proposed correction knowledge verified |
| 7 Evaluation | In progress | Phase 15 expands deterministic evidence-quality coverage to 30 cases; real-model accuracy remains unscored pending independently adjudicated labels |
| 8 Runbooks | Implemented / partially Verified | Knowledge category/search/versioning supports runbooks; specialized runbook library remains |
| 9 Safe remediation | Implemented / safety-verified | Read-only allowlist and emergency disable implemented; no changing action executes |
| 10 Multi-provider | Implemented / partially Verified | Docker provider interface live; Kubernetes/AWS remain unavailable external providers |
| 11 Security | Implemented / partially Verified | Optional API key, restricted CORS, secret redaction, read-only socket mount and remediation disable; RBAC, MFA, TLS and secrets-manager integration are not implemented |
| 12 Dashboard | Tested / Partially Verified | Typecheck/build and live browser desktop/narrow smoke checks passed with no console or failed-request errors; complete GUI mutation workflow remains unverified |
| 13 Reliability testing | Tested / Partially Verified | 44 backend tests and live Docker/Ollama scenarios passed; two historical model investigations and one pre-fix follow-up reassessment remain recorded as failed |
| 14 Deployment | Tested / Partially Verified | Local Compose services are healthy and local/telemetry/production configurations validate; production secrets, TLS, authorization and PostgreSQL remain unimplemented |

## Continued runtime QA status

| Gate | Status | Evidence |
|---|---|---|
| Docker daemon recovery | Verified | Docker Desktop and Engine reconnected; backend/collector/monitor and Compose became healthy |
| Ollama outage/recovery | Verified | Timeout was observed, health degraded correctly, queued investigation completed after Ollama restart |
| Invalid Ollama endpoint | Verified | Connection refusal was reported without crashing the API |
| Backend restart persistence | Verified | Incident and knowledge APIs retained existing data |
| Dashboard restart | Verified | HTTP 200 and `/api/health` proxy 200 after restart |
| Container restart persistence | Verified | Metrics increased after restart; incidents remained 5 and knowledge remained 2 |
| Event reconnection/deduplication | Verified / Partial | Collector stayed running with 0 reconnects; duplicate-event deduplication passed synthetic tests |
| Real Qwen inference | Verified | Qwen 2.5 3B produced `/analyze` text and completed incident investigations 21/22 |
| Docker failure scenarios | Verified | The five labeled stopped, restart-loop, unhealthy, CPU and memory scenarios each generated matching incidents; labeled containers were cleaned up |
| Approved follow-up/reassessment | Verified after fix | Initial log reassessment #53 reproduced `KeyError: 'line'`; fix and regression test added; post-fix reassessment #55 completed with one collected log marker |
| Real Qwen evaluation | Verified as inference only | Five curated cases completed with `qwen2.5:3b`; root-cause accuracy intentionally remains unscored without independently adjudicated labels |
| Browser desktop/narrow layout | Verified | Browser automation found no overflow, console, page or failed-request errors; requested 390 px rendered as 300 px CSS width |
| Browser workflows | Partially Verified | Live incident/evidence/knowledge UI rendered; follow-up approval was tested through the API, not the dashboard click path |
| Authentication across protected routes | Implemented / Verified locally | Local profile has API key disabled; unit-test middleware and production key requirement verified |

## Latest local validation (2026-11-26)

- `python -m unittest discover -s tests -p "test_*.py" -v`: **44 passed**.
- Python compilation, frontend typecheck and production build passed.
- Core, telemetry and production Compose configuration checks passed.
- Live `/health` reported API, Docker and Ollama connected; monitor and event
  collector were running with no errors after recovery.
- The real Qwen evaluation completed 5/5 cases. Its report explicitly leaves
  root-cause accuracy unscored.
- SQLite schema 8 integrity check returned `ok`; live counts were 35 incidents,
  49 investigations, 28,560 metric samples, 193 Docker events, 2 knowledge
  records, 3 knowledge versions, 2 feedback records, 2 evaluation runs and 3
  follow-ups. No database rows were deleted during QA.


## Phase 15 — AI investigation reliability (implementation started)

Objective: improve evidence-to-claim fidelity before expanding provider or deployment scope.

Implemented in this milestone:
- Source-aware deterministic checks for OOM claims, exit codes, runtime state, Docker health status, CPU/memory saturation, restart loops and operator-intent claims.
- Contradictory evidence downgrades a finding; missing typed evidence prevents a finding from remaining a confirmed fact.
- OOMKilled=true or a Docker OOM event can support an OOM observation; OOMKilled=false contradicts a positive OOM claim. Exit code 137 and high memory usage alone are not treated as OOM proof.
- Operator-action annotations remain explicitly unverified context.
- Added 18 additional deterministic fixtures (30 total) with case-specific review criteria.
- Evaluation metrics now count raw evidence references, unsupported findings, omitted findings and downgraded findings before filtering. Root-cause accuracy remains null without adjudicated labels.
- Real-model evaluation can select up to 30 cases; default remains five for a shorter local run.

Remaining Phase 15 gates:
- Run all 30 real-model cases against the local Ollama instance and review outputs.
- Add independently adjudicated expected root-cause labels before calculating accuracy.
- Compare baseline and revised prompts/validator using the same model, dataset and runtime settings.
- Review semantic guardrail edge cases with human operators; these checks are conservative heuristics, not general natural-language entailment.
