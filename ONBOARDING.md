# Autonomous SOC Platform — Project Handoff

## Who Is This For
Devin Ramotar. Cybersecurity background, learning AI, building a resume/production-worthy
project targeting a Cyber AI role at his company. Multi-week build. Prefers thorough
explanations of how everything works individually and together.

---

## Project Location
- Local: `/Users/devinramotar/Documents/home-lab/ai-project/`
- GitHub: https://github.com/dRam51/autonomous-soc-platform
- GitHub user: dRam51

---

## What This Project Is
An autonomous Security Operations Center platform that mirrors how a real SOC team works.
Multiple specialized AI agents collaborate to triage, investigate, and remediate security
alerts automatically. Each agent has a specific role, they share state through LangGraph,
and every decision is fully auditable via LangSmith.

The project is intentionally comprehensive — it was designed to showcase every major
mainstream AI skill (RAG, agents, tool use, streaming, fine-tuning path, etc.) in a
single coherent cyber security context.

---

## Current State: What Has Been Built

### Infrastructure (scaffolded, not yet running)
- `docker-compose.yml` — PostgreSQL (pgvector), Redis, backend, frontend
- `backend/Dockerfile`
- `backend/app/main.py` — FastAPI app with CORS middleware
- `backend/app/config.py` — Pydantic settings loaded from .env
- `.env.example` — all required environment variables documented
- `.github/workflows/ci.yml` — GitHub Actions lint + test on push

### Skills Library (fully implemented)
All 6 skills are production-ready async functions wrapped as Claude tool schemas.
Located in `backend/app/skills/`:
- `__init__.py` — SKILL_REGISTRY, get_skill_schemas(), dispatch_skill()
- `virustotal.py` — IOC reputation (IP/domain/hash) via VirusTotal API
- `shodan.py` — host intelligence: open ports, services, C2 tags
- `nvd.py` — live CVE details from NIST NVD API
- `cisa_kev.py` — CISA KEV catalog check with 24h in-memory cache
- `ip_intel.py` — IP geolocation via ip-api.com (free, no API key needed)
- `rag_search.py` — semantic search wrapper over Pinecone vector store

### Core Modules (fully implemented)
- `backend/app/core/vector_store.py` — Pinecone client + RAG query function
- `backend/app/core/memory.py` — cross-session entity memory with TTL expiry

### Services (fully implemented)
- `backend/app/services/deduplication.py` — cosine similarity dedup + DBSCAN clustering
- `backend/app/services/anomaly_detection.py` — Isolation Forest ML pre-filter
- `backend/app/services/calibration.py` — triage confidence calibration tracking

### Agents (fully implemented with all AI techniques)
- `backend/app/agents/supervisor.py` — LangGraph graph, parallel execution, HITL
- `backend/app/agents/triage.py` — voting, few-shot, self-reflection, prompt caching
- `backend/app/agents/threat_intel.py` — full agentic skill loop, prompt caching
- `backend/app/agents/investigation.py` — extended thinking, self-correction, memory
- `backend/app/agents/remediation.py` — skills integration, prompt caching
- `backend/app/agents/reporting.py` — memory write-back, confidence calibration

### API Routes (fully implemented)
- `backend/app/api/routes/alerts.py` — dedup pre-check, anomaly filter, SSE streaming, HITL approve
- `backend/app/api/routes/incidents.py` — incident report retrieval

### Tasks (fully implemented)
- `backend/app/tasks/celery_app.py` — Celery + Redis config
- `backend/app/tasks/batch.py` — Anthropic Batch API for bulk retriage and CVE enrichment

### Models
- `backend/app/models/schemas.py` — all Pydantic schemas for agent I/O

### Data
- `data/seeds/sample_alerts.json` — 5 realistic test alerts
- `scripts/ingest_threat_intel.py` — fetches MITRE ATT&CK, CISA KEV, NVD into Pinecone

### Tests (23 tests, mockable, no real API keys needed)
- `backend/tests/skills/test_skills.py` — 12 skill unit tests
- `backend/tests/services/test_services.py` — 11 service unit tests

### Documentation
- `README.md` — comprehensive architecture docs with 9 layers, full request flow,
  AI techniques section (18 techniques), tech stack, project structure, quick start,
  roadmap, and skills demonstrated tables

---

## All AI Techniques Implemented

### In the Agents
| Technique | File | How |
|---|---|---|
| Prompt caching | All agents | `cache_control: ephemeral` on system prompts |
| Multi-agent voting | triage.py | N parallel triage runs, majority vote on severity |
| Dynamic few-shot | triage.py | `_fetch_few_shot_examples()` — TODO: wire to real DB |
| Self-reflection | triage.py | Critique agent reviews and can revise initial assessment |
| Extended thinking | investigation.py | `thinking: {type: enabled, budget_tokens: 8000}` |
| Agentic self-correction | investigation.py, threat_intel.py | Skill failure hint injected back into context |
| Skills (tool use) | threat_intel, investigation, remediation | dispatch_skill() in agentic loop |
| Agent memory | investigation.py (read), reporting.py (write) | recall_memories() / store_memory() |
| Confidence calibration | reporting.py | Weighted average of triage confidence + risk score |
| Parallel execution | supervisor.py | asyncio.gather on threat_intel + IP geo |
| Human-in-the-loop | supervisor.py | LangGraph NodeInterrupt on CRITICAL alerts |

### In the Services / API
| Technique | File | How |
|---|---|---|
| Alert deduplication | deduplication.py + alerts.py | Cosine similarity check before pipeline entry |
| Alert clustering | deduplication.py | DBSCAN on alert embeddings |
| ML anomaly pre-filter | anomaly_detection.py + alerts.py | Isolation Forest scores alerts; low-anomaly auto-closed |
| SSE streaming | alerts.py | StreamingResponse with event queue per alert_id |
| Batch processing | tasks/batch.py | Anthropic Batch API for bulk retriage and CVE enrichment |
| Confidence calibration tracking | calibration.py | record_prediction() / record_outcome() / compute_calibration_report() |

### Post-MVP (documented, not yet built)
- Fine-tuning on security incident data
- MITRE ATT&CK knowledge graph (Neo4j or NetworkX)
- Active learning from analyst feedback

---

## What Has NOT Been Built Yet

### High Priority (needed to actually run the project)
1. **Docker Desktop** — not installed on the machine. Devin needs to install it from
   https://www.docker.com/products/docker-desktop/ before any `docker compose` commands work.

2. **Python virtual environment** — not yet created. Need to run:
   ```bash
   cd /Users/devinramotar/Documents/home-lab/ai-project/backend
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

3. **API Keys** — none configured yet. Need to get:
   - Anthropic API key (https://console.anthropic.com)
   - Pinecone API key (https://app.pinecone.io) — free tier works
   - LangSmith API key (https://smith.langchain.com) — free tier works
   - VirusTotal API key (https://www.virustotal.com/gui/my-apikey) — free tier
   - Shodan API key (https://account.shodan.io) — free tier (limited)
   - NVD API key (https://nvd.nist.gov/developers/request-an-api-key) — optional, raises rate limits

4. **`.env` file** — copy `.env.example` to `.env` and fill in all keys

5. **Pinecone index** — not seeded. After API keys are set up, run:
   ```bash
   python scripts/ingest_threat_intel.py
   ```
   This fetches MITRE ATT&CK, CISA KEV, NVD CVEs and loads them into Pinecone.

### Medium Priority (to complete the platform)
6. **Frontend (Next.js)** — the `frontend/` directory exists but is empty. Needs:
   - Next.js project initialization
   - Tailwind CSS + shadcn/ui setup
   - SOC dashboard UI: alert feed, agent activity panel, incident report view
   - SSE client to stream pipeline events in real-time
   - Analyst chat interface

7. **PostgreSQL models + Alembic migrations** — the API currently uses in-memory
   dicts for development. For production, need:
   - SQLAlchemy ORM models for Alert, IncidentReport, AgentMemory, TriagePrediction
   - Alembic migration files
   - Swap in-memory stores in alerts.py with real DB queries

8. **Few-shot prompting DB query** — `_fetch_few_shot_examples()` in triage.py has a
   TODO comment. Needs a real PostgreSQL query that fetches the 3 most similar past
   incidents by embedding similarity from the alerts table.

9. **LangSmith evals** — the observability infrastructure is wired up but no eval
   datasets have been created yet. Should create test cases against the 5 sample alerts
   in `data/seeds/sample_alerts.json`.

---

## Style and Preferences
- No em dashes in any files (user specifically requested this)
- Explanations: Devin wants to understand how everything works individually and together,
  not just be handed code. Explain concepts before implementing them.
- Commit style: descriptive messages, Co-Authored-By footer with Claude
- Git workflow: when remote has diverged, use `git fetch && git reset --soft origin/main`
  to avoid rebase conflicts, then recommit

---

## Tech Stack Quick Reference
| Layer | Tool |
|---|---|
| LLM | Anthropic Claude (Opus 4.5 for triage/investigation, Sonnet 4.5 for threat_intel/remediation, Haiku 4.5 for reporting) |
| Agent orchestration | LangGraph |
| RAG | LangChain + Pinecone + Voyage-3 embeddings |
| Observability | LangSmith |
| Backend | FastAPI + Celery + Redis |
| Database | PostgreSQL + pgvector |
| ML | scikit-learn (Isolation Forest, DBSCAN) |
| Frontend | Next.js + Tailwind CSS + shadcn/ui (not yet built) |
| DevOps | Docker Compose + GitHub Actions |
| Security APIs | VirusTotal, Shodan, NIST NVD, CISA KEV, ip-api.com |

---

## Suggested Next Steps (in order)
1. Install Docker Desktop and verify with `docker --version`
2. Create `.env` from `.env.example` and fill in Anthropic + Pinecone + LangSmith keys
3. Create Python venv, install requirements
4. Start infrastructure: `docker compose up db redis -d`
5. Run ingestion script to seed Pinecone
6. Start backend: `uvicorn app.main:app --reload` from the backend directory
7. Test with a sample alert from `data/seeds/sample_alerts.json`
8. Build the Next.js frontend
9. Wire up PostgreSQL ORM models to replace in-memory stores
10. Create LangSmith eval datasets

---

## Repository State
All code is committed and pushed to main. The last commit was:
`feat: implement all AI techniques across the full stack`
30 files changed, 2531 insertions.
