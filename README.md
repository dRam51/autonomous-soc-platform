# Autonomous SOC Platform

An AI-powered Security Operations Center that mirrors how a real SOC team works — multiple specialized agents collaborating to triage, investigate, and remediate security alerts automatically.

## Architecture

```
Alert Ingestion
      │
      ▼
┌─────────────────────┐
│   Supervisor Agent  │  ← LangGraph orchestration
│   (LangGraph FSM)   │
└──────────┬──────────┘
           │
    ┌──────┼──────────────────┐
    ▼      ▼                  ▼
Triage  Threat Intel    Investigation
Agent     Agent            Agent
    │      │                  │
    └──────┴──────────────────┘
                  │
           Remediation
              Agent
                  │
            Reporting
              Agent
                  │
                  ▼
          Incident Report
```

### Agents

| Agent | Model | Role |
|---|---|---|
| **Supervisor** | — | LangGraph orchestrator, routes between agents based on severity |
| **Triage** | Claude Opus | Normalizes alerts, scores severity, maps to MITRE ATT&CK |
| **Threat Intel** | Claude Sonnet | RAG over MITRE ATT&CK + CVE/NVD + CISA KEV |
| **Investigation** | Claude Opus | Deep-dives high/critical alerts, reconstructs attack chain |
| **Remediation** | Claude Sonnet | Generates prioritized playbooks (immediate → long-term) |
| **Reporting** | Claude Haiku | Compiles structured incident reports + executive summaries |

## Tech Stack

| Layer | Technology |
|---|---|
| **LLM** | Anthropic Claude (Opus / Sonnet / Haiku) |
| **Agent Orchestration** | LangGraph |
| **RAG** | LangChain + Pinecone |
| **Embeddings** | Voyage-3 (Anthropic) |
| **Observability** | LangSmith |
| **Backend** | FastAPI + Celery + Redis |
| **Database** | PostgreSQL + pgvector |
| **Frontend** | Next.js + Tailwind CSS + shadcn/ui |
| **DevOps** | Docker Compose + GitHub Actions |

## Threat Intelligence Sources

- **MITRE ATT&CK** — Full TTP database (STIX format)
- **NIST NVD** — CVE feed with CVSS scores
- **CISA KEV** — Known Exploited Vulnerabilities catalog
- **VirusTotal** — IOC enrichment

## Quick Start

### 1. Clone & configure

```bash
git clone https://github.com/dRam51/autonomous-soc-platform.git
cd autonomous-soc-platform
cp .env.example .env
# Fill in your API keys in .env
```

### 2. Start infrastructure

```bash
docker compose up db redis -d
```

### 3. Seed the vector store

```bash
cd backend
pip install -r requirements.txt
python ../scripts/ingest_threat_intel.py
```

### 4. Run the platform

```bash
docker compose up
```

- **Backend API:** http://localhost:8000
- **API Docs:** http://localhost:8000/docs
- **Frontend:** http://localhost:3000

### 5. Submit a test alert

```bash
curl -X POST http://localhost:8000/api/v1/alerts/ \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Suspicious PowerShell Execution",
    "description": "PowerShell spawned by Word.exe with encoded command",
    "source": "EDR",
    "source_ip": "192.168.1.105",
    "destination_ip": "203.0.113.42",
    "affected_host": "WORKSTATION-042",
    "iocs": ["203.0.113.42"]
  }'
```

## Project Structure

```
autonomous-soc-platform/
├── backend/
│   ├── app/
│   │   ├── agents/          # LangGraph agents (supervisor, triage, etc.)
│   │   ├── api/routes/      # FastAPI endpoints
│   │   ├── core/            # Vector store, database
│   │   ├── models/          # Pydantic schemas
│   │   └── tasks/           # Celery workers
│   └── tests/
├── frontend/                # Next.js SOC dashboard
├── scripts/
│   └── ingest_threat_intel.py   # Seeds Pinecone with threat intel
├── data/seeds/              # Sample alerts for testing
├── .github/workflows/       # CI/CD
└── docker-compose.yml
```

## Roadmap

- [ ] Week 1 — Core infrastructure + threat intel ingestion
- [ ] Week 2 — Triage + Threat Intel agents
- [ ] Week 3 — Investigation + Remediation + Reporting agents
- [ ] Week 4 — Next.js dashboard + LangSmith evals + Docker polish

## Skills Demonstrated

- Multi-agent orchestration with LangGraph
- RAG pipelines with Pinecone vector database
- Claude API with structured tool use
- Async FastAPI backend with Celery task queue
- LLM observability with LangSmith
- Production Docker deployment

---

Built with [Claude](https://anthropic.com) + LangGraph
