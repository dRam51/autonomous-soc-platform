# Autonomous SOC Platform

An AI-powered Security Operations Center that mirrors how a real SOC team works, with multiple specialized agents collaborating to triage, investigate, and remediate security alerts automatically.

When a security alert fires, the platform does what a 5-person SOC team would do, except in seconds, with every decision fully auditable.

---

## Table of Contents

- [System Overview](#system-overview)
- [Full Request Flow](#full-request-flow)
- [Architecture Layers](#architecture-layers)
  - [Layer 1: API (FastAPI)](#layer-1-api-fastapi)
  - [Layer 2: Task Queue (Celery + Redis)](#layer-2-task-queue-celery--redis)
  - [Layer 3: Agent Orchestration (LangGraph)](#layer-3-agent-orchestration-langgraph)
  - [Layer 4: The Agents (Claude API)](#layer-4-the-agents-claude-api)
  - [Layer 5: RAG Pipeline (LangChain + Pinecone)](#layer-5-rag-pipeline-langchain--pinecone)
  - [Layer 6: Data Persistence (PostgreSQL)](#layer-6-data-persistence-postgresql)
  - [Layer 7: Observability (LangSmith)](#layer-7-observability-langsmith)
  - [Layer 8: Dashboard (Next.js)](#layer-8-dashboard-nextjs)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Quick Start](#quick-start)
- [Roadmap](#roadmap)
- [Skills Demonstrated](#skills-demonstrated)

---

## System Overview

```
[Security Tool]          Alert fires (EDR, SIEM, firewall, IDS)
      |
      v
[FastAPI Backend]        Server receives alert via HTTP
      |
      v
[Celery + Redis]         Hands job to background worker (API stays responsive)
      |
      v
[LangGraph Supervisor]   Orchestrator decides which agents run and in what order
      |
   +--+------------------------------------------+
   v           v              v               v
Triage     Threat Intel   Investigation   Remediation
Agent        Agent           Agent           Agent
   +--+------------------------------------------+
      |
      v
[Reporting Agent]        Compiles everything into a structured incident report
      |
      v
[PostgreSQL]             Report saved to database
      |
      v
[Next.js Dashboard]      Analyst reviews the report in the UI
```

---

## Full Request Flow

Here is what happens from the moment an alert arrives to the moment an analyst sees the report:

```
1.  CrowdStrike EDR fires an alert
2.  Alert hits POST /api/v1/alerts/ (FastAPI)
3.  FastAPI validates data (Pydantic), saves to PostgreSQL, returns 202 immediately
4.  FastAPI hands job to Celery via Redis
5.  Celery worker picks it up, calls LangGraph supervisor
6.  LangGraph runs Triage agent
        -> Claude Opus analyzes alert, returns severity = HIGH
7.  LangGraph runs Threat Intel agent
        a. Queries Pinecone: "PowerShell execution MITRE T1059 LOLBins"
        b. Gets back 5 chunks: 3 MITRE TTPs, 1 CISA KEV entry, 1 CVE
        c. Sends those chunks + alert context to Claude Sonnet
        d. Returns: related CVEs, threat actors, risk_score = 8.7
8.  LangGraph hits should_escalate() -> severity = HIGH -> runs Investigation agent
9.  Investigation agent receives full state (alert + triage + threat intel)
        -> Reconstructs attack chain, identifies lateral movement risk
10. Remediation agent generates prioritized playbook
11. Reporting agent writes executive summary, compiles IncidentReport
12. Report saved to PostgreSQL
13. LangSmith recorded every Claude call (steps 6-11) with full traces
14. Analyst opens Next.js dashboard, sees the completed incident report
```

---

## Architecture Layers

### Layer 1: API (FastAPI)

**Role:** The front door of the entire system. Every external interaction passes through here.

FastAPI is *async-native*, meaning it handles many simultaneous requests without blocking. This is critical because agent pipelines take 15-45 seconds, so the server must stay responsive while they run in the background.

**Endpoints:**

```
POST /api/v1/alerts/              Receive a new alert, kick off the pipeline
GET  /api/v1/alerts/              List all ingested alerts
GET  /api/v1/alerts/{id}          Get a specific alert and its current status
GET  /api/v1/alerts/{id}/incident Get the finished incident report for an alert
GET  /api/v1/incidents/           List all incident reports
```

Incoming data is validated automatically by **Pydantic schemas** before it ever touches business logic. If a required field is missing or the wrong type, FastAPI rejects it with a clear error, so no defensive code is needed inside the agents.

---

### Layer 2: Task Queue (Celery + Redis)

**Role:** Run long agent pipelines in the background without blocking the API.

**The problem:** If the API had to wait 30 seconds for 5 agents to finish before responding, every alert submission would feel broken and would time out in production.

**The solution (restaurant analogy):**
- **FastAPI** (waiter) takes your order immediately and gives you a receipt (202 Accepted)
- **Redis** (order ticket rail) holds the job between the waiter and kitchen
- **Celery** (kitchen) does the actual work asynchronously

```
User submits alert
       |
       v
FastAPI responds IMMEDIATELY -> "Received, processing..." (202)
       |
       v
Celery picks up the job from Redis
       |
       v
Agents run (15-45 seconds)
       |
       v
Result saved to PostgreSQL; analyst can now retrieve the report
```

Redis also stores task results so Celery workers can report success or failure back through the same channel.

---

### Layer 3: Agent Orchestration (LangGraph)

**Role:** The nervous system that connects all agents into a coherent, stateful pipeline.

LangGraph models the SOC workflow as a **state machine graph** where nodes are agents, edges are paths between them, and a shared state object carries data through the entire pipeline. Each agent reads from the state, does its work, and writes its output back.

**The shared state object:**

```python
class SOCState(TypedDict):
    alert_id: str
    alert: AlertCreate              # The raw incoming alert
    triage: TriageResult            # Filled by Triage agent
    threat_intel: ThreatIntelResult # Filled by Threat Intel agent
    investigation: InvestigationResult  # Filled by Investigation agent
    remediation: RemediationResult  # Filled by Remediation agent
    incident_report: IncidentReport # Filled by Reporting agent
```

Every agent receives the *entire* state, so Investigation can reason over what Triage and Threat Intel already discovered. No agent is isolated; they all build on each other's work.

**The graph with routing logic:**

```
START
  |
  v
Triage          Always runs first
  |
  v
Threat Intel    Always runs second (RAG enrichment)
  |
  v
should_escalate()   <- Conditional edge: checks triage severity
  |
  +-- severity = CRITICAL / HIGH / MEDIUM -> Investigation -> Remediation
  |
  +-- severity = LOW / INFO -> Remediation (skips investigation)
        |
        v
      Reporting
        |
       END
```

The conditional routing is intentional. Low-severity alerts don't need a deep investigation, so we skip it. This saves cost, time, and keeps the pipeline proportional to actual risk.

---

### Layer 4: The Agents (Claude API)

Each agent is a Claude API call with a specific system prompt, a tool definition, and forced structured output. Here is how each one is designed:

| Agent | Model | Why That Model | What It Does |
|---|---|---|---|
| **Supervisor** | N/A | LangGraph FSM, no LLM needed | Routes between agents based on state |
| **Triage** | Claude Opus | Needs the deepest reasoning for first assessment | Scores severity, maps to MITRE ATT&CK techniques |
| **Threat Intel** | Claude Sonnet | Balanced, mostly synthesizing RAG context | Enriches with CVEs, threat actors, risk score |
| **Investigation** | Claude Opus | Deep multi-step reasoning required | Reconstructs attack chain, lateral movement |
| **Remediation** | Claude Sonnet | Strong reasoning, cost-efficient | Generates immediate / short-term / long-term playbook |
| **Reporting** | Claude Haiku | Fast and cheap, used for summarization | Executive summary + compiles full report |

**Why different models per agent?**
Cost and capability optimization. Claude Opus is the most capable but slowest and most expensive. We only spend Opus budget where deep reasoning is critical (triage, investigation). Haiku is fast and cheap, which is exactly right for summarization. This is a production pattern, not an accident.

**Why every agent uses structured tool use:**

Instead of asking Claude to "return JSON", every agent defines a tool with an explicit schema and forces Claude to call it:

```python
TRIAGE_TOOLS = [{
    "name": "submit_triage",
    "input_schema": {
        "properties": {
            "severity": {"enum": ["critical","high","medium","low","info"]},
            "confidence": {"type": "number"},
            "reasoning": {"type": "string"},
            "mitre_techniques": {"type": "array"}
        }
    }
}]
```

This guarantees the output is always valid, typed, and parseable, with no fragile regex or text extraction. If Claude tries to respond in prose, the API rejects it. This is what makes the pipeline reliable in production.

---

### Layer 5: RAG Pipeline (LangChain + Pinecone)

**Role:** Give agents access to a real-time, searchable knowledge base of threat intelligence.

**What RAG is:** Retrieval Augmented Generation. Instead of relying purely on Claude's training data (which may be outdated or lack specifics), we give the model a knowledge base to look things up in, like an open-book exam.

**How it works:**

```
Threat Intel Agent runs
        |
        v
Build a search query from alert + triage results
        |
        v
Query Pinecone: find the 5 most semantically similar chunks
        |
        v
Pinecone returns relevant MITRE TTPs, CVEs, KEV entries
        |
        v
Those chunks are injected into the Claude prompt as context
        |
        v
Claude reasons over real, current threat data, not just training
```

**How vectors work:** Every chunk of text is converted to a list of ~1024 numbers (a vector/embedding) that captures its meaning mathematically. Similar concepts produce similar numbers. When you search, your query also becomes a vector and Pinecone finds the closest matches. This is *semantic search* that finds conceptually related content, not just keyword matches.

**What is indexed in Pinecone:**

| Source | What It Contains | Why It Matters |
|---|---|---|
| **MITRE ATT&CK** | Every known attack technique with descriptions, platforms, kill chain phases | Lets agents map alerts to TTPs with context |
| **CISA KEV** | Every CVE actively exploited in the wild, required action, ransomware usage | Prioritizes vulnerabilities that are real threats now |
| **NIST NVD** | Recent CVEs with CVSS scores and descriptions | Provides severity and impact context |

The `scripts/ingest_threat_intel.py` script fetches all three sources, chunks them, embeds them with Voyage-3, and upserts into Pinecone. Run it once to seed, then periodically to keep it fresh.

---

### Layer 6: Data Persistence (PostgreSQL)

**Role:** Store all structured data (alerts, agent outputs, incident reports) durably and queryably.

The project uses two storage systems for two different jobs:

| Store | What It Holds | Why |
|---|---|---|
| **PostgreSQL** | Alerts, incident reports, agent output history | Structured, relational, queryable with SQL |
| **Pinecone** | Threat intelligence embeddings | Optimized purely for vector similarity search |

---

### Layer 7: Observability (LangSmith)

**Role:** Record, trace, debug, and evaluate every LLM call the system makes.

In a normal application you can add print statements and read logs. With multi-agent LLM systems, failures are subtler. An agent might produce a plausible-looking but wrong answer. LangSmith solves this.

**What LangSmith captures per agent run:**

```
Without LangSmith:                  With LangSmith:
"Why did triage give the            Full trace showing:
 wrong severity?"          ->       +-- Exact system prompt sent
                                    +-- Exact user message
                                    +-- Which RAG chunks were retrieved
                                    +-- Exact Claude response
                                    +-- Token count + latency
                                    +-- Where in the graph it went wrong
```

**Evals:** LangSmith also enables automated evaluation. You can define test cases (e.g., "this known-bad alert must score at least HIGH") and run them on a schedule to catch regressions as you iterate on prompts.

This is what separates an AI prototype from a production system. You can measure and prove your agents are performing correctly.

---

### Layer 8: Dashboard (Next.js)

**Role:** The analyst-facing interface for the entire platform.

Built with Next.js + Tailwind CSS + shadcn/ui. Key views:

- **Alert feed:** live list of incoming alerts with severity badges and pipeline status
- **Agent activity panel:** shows which agents have fired and their outputs in real time
- **Incident report view:** full structured report with triage, threat intel, investigation, remediation, and executive summary
- **Analyst chat:** natural language interface to query alerts ("show me all critical alerts from the last 24 hours involving lateral movement")

---

## Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| **LLM** | Anthropic Claude (Opus / Sonnet / Haiku) | Core reasoning for all agents |
| **Agent Orchestration** | LangGraph | Stateful multi-agent graph |
| **RAG** | LangChain + Pinecone | Threat intel retrieval pipeline |
| **Embeddings** | Voyage-3 (Anthropic) | Text to vector conversion |
| **Observability** | LangSmith | LLM tracing, debugging, evals |
| **Backend** | FastAPI + Celery + Redis | Async API + background task queue |
| **Database** | PostgreSQL + pgvector | Structured data + vector support |
| **Frontend** | Next.js + Tailwind + shadcn/ui | SOC analyst dashboard |
| **DevOps** | Docker Compose + GitHub Actions | Containerization + CI |

---

## Project Structure

```
autonomous-soc-platform/
+-- backend/
|   +-- app/
|   |   +-- agents/
|   |   |   +-- supervisor.py      # LangGraph graph definition + routing logic
|   |   |   +-- triage.py          # Severity scoring + MITRE mapping
|   |   |   +-- threat_intel.py    # RAG enrichment (CVEs, TTPs, threat actors)
|   |   |   +-- investigation.py   # Attack chain reconstruction
|   |   |   +-- remediation.py     # Playbook generation
|   |   |   +-- reporting.py       # Incident report compilation
|   |   +-- api/routes/
|   |   |   +-- alerts.py          # Alert ingestion + pipeline trigger
|   |   |   +-- incidents.py       # Incident report retrieval
|   |   +-- core/
|   |   |   +-- vector_store.py    # Pinecone client + RAG query function
|   |   +-- models/
|   |   |   +-- schemas.py         # Pydantic schemas for all agent I/O
|   |   +-- tasks/
|   |   |   +-- celery_app.py      # Celery + Redis configuration
|   |   +-- config.py              # Settings loaded from .env
|   |   +-- main.py                # FastAPI app + middleware
|   +-- tests/
|   +-- requirements.txt
+-- frontend/                      # Next.js SOC dashboard
+-- scripts/
|   +-- ingest_threat_intel.py     # Fetches + indexes MITRE/CVE/KEV into Pinecone
+-- data/
|   +-- seeds/
|       +-- sample_alerts.json     # 5 realistic test alerts
+-- .github/
|   +-- workflows/
|       +-- ci.yml                 # Lint + test on every push
+-- .env.example                   # All required environment variables
+-- docker-compose.yml             # PostgreSQL, Redis, backend, frontend
```

---

## Quick Start

### Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/)
- Python 3.12+
- API keys: Anthropic, Pinecone, LangSmith (all have free tiers)

### 1. Clone and configure

```bash
git clone https://github.com/dRam51/autonomous-soc-platform.git
cd autonomous-soc-platform
cp .env.example .env
# Open .env and fill in your API keys
```

### 2. Start infrastructure

```bash
# Start PostgreSQL and Redis only (lightweight, no agents yet)
docker compose up db redis -d
```

### 3. Install backend dependencies and seed the vector store

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Fetch MITRE ATT&CK, CISA KEV, and NVD CVEs, embed them, and upload to Pinecone
python ../scripts/ingest_threat_intel.py
```

### 4. Run the full platform

```bash
docker compose up
```

- **Backend API:** http://localhost:8000
- **API Docs (auto-generated):** http://localhost:8000/docs
- **Frontend Dashboard:** http://localhost:3000
- **LangSmith traces:** https://smith.langchain.com

### 5. Submit a test alert

```bash
curl -X POST http://localhost:8000/api/v1/alerts/ \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Suspicious PowerShell Execution with Encoded Command",
    "description": "PowerShell spawned by Word.exe with base64-encoded argument, attempted outbound connection",
    "source": "CrowdStrike EDR",
    "source_ip": "192.168.1.105",
    "destination_ip": "203.0.113.42",
    "affected_host": "WORKSTATION-042",
    "iocs": ["203.0.113.42"]
  }'
```

Then poll for the incident report:

```bash
curl http://localhost:8000/api/v1/alerts/{alert_id}/incident
```

Sample alerts for testing are in `data/seeds/sample_alerts.json`.

---

## Skills Demonstrated

| Skill | Where |
|---|---|
| Multi-agent orchestration | LangGraph supervisor + conditional routing |
| RAG pipelines | LangChain + Pinecone + Voyage-3 embeddings |
| Structured LLM tool use | Every agent uses forced tool calling |
| Model tiering | Opus / Sonnet / Haiku matched to task complexity |
| Async backend engineering | FastAPI + Celery + Redis |
| LLM observability + evals | LangSmith tracing on every agent call |
| Production containerization | Docker Compose with health checks |
| CI/CD | GitHub Actions lint + test on every push |
| Cyber domain expertise | MITRE ATT&CK, CVE/NVD, CISA KEV, real IOC patterns |

---
