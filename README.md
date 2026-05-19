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
  - [Layer 5: Skills Library](#layer-5-skills-library)
  - [Layer 6: RAG Pipeline (LangChain + Pinecone)](#layer-6-rag-pipeline-langchain--pinecone)
  - [Layer 7: Data Persistence (PostgreSQL)](#layer-7-data-persistence-postgresql)
  - [Layer 8: Observability (LangSmith)](#layer-8-observability-langsmith)
  - [Layer 9: Dashboard (Next.js)](#layer-9-dashboard-nextjs)
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
      |           ^agents call skills at runtime^
      |
      v
[Skills Library]         Reusable callable tools available to all agents
  |-- VirusTotal         IOC reputation lookups
  |-- Shodan             Host and IP intelligence
  |-- NVD API            Live CVE data
  |-- CISA KEV           Actively exploited vulnerability checks
  |-- ip-api.com         IP geolocation
  |-- RAG Search         Semantic search over threat intel corpus
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
        -> Calls skills: rag_search("PowerShell encoded command MITRE")
        -> Claude Opus analyzes alert + skill results, returns severity = HIGH
7.  LangGraph runs Threat Intel agent
        -> Calls skills: virustotal("203.0.113.42"), cisa_kev("CVE-2021-44228")
        -> Calls skills: rag_search("T1059 LOLBins threat actors")
        -> Gets back: 47/92 VT detections, KEV confirmed, 3 MITRE TTP chunks
        -> Claude Sonnet synthesizes all results, returns risk_score = 8.7
8.  LangGraph hits should_escalate() -> severity = HIGH -> runs Investigation agent
9.  Investigation agent receives full state (alert + triage + threat intel)
        -> Calls skills: shodan("203.0.113.42"), geolocate_ip("203.0.113.42")
        -> Shodan: port 4444 open, tagged C2. Geo: Russia, known malicious ASN
        -> Reconstructs attack chain, flags lateral movement risk
10. Remediation agent generates prioritized playbook using CVE + KEV skill data
11. Reporting agent writes executive summary, compiles IncidentReport
12. Report saved to PostgreSQL
13. LangSmith recorded every Claude call and every skill invocation (steps 6-11)
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
Agents run, calling skills as needed (15-45 seconds)
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
Threat Intel    Always runs second (RAG enrichment + live skill calls)
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

Each agent is a Claude API call with a specific system prompt, a set of available skills, and forced structured output. Here is how each one is designed:

| Agent | Model | Why That Model | What It Does | Skills Available |
|---|---|---|---|---|
| **Supervisor** | N/A | LangGraph FSM, no LLM needed | Routes between agents based on state | None |
| **Triage** | Claude Opus | Needs the deepest reasoning for first assessment | Scores severity, maps to MITRE ATT&CK | rag_search |
| **Threat Intel** | Claude Sonnet | Balanced, mostly synthesizing data from multiple sources | Enriches with CVEs, threat actors, risk score | virustotal, cisa_kev, nvd, rag_search |
| **Investigation** | Claude Opus | Deep multi-step reasoning required | Reconstructs attack chain, lateral movement | shodan, geolocate_ip, virustotal, rag_search |
| **Remediation** | Claude Sonnet | Strong reasoning, cost-efficient | Generates immediate / short-term / long-term playbook | nvd, cisa_kev |
| **Reporting** | Claude Haiku | Fast and cheap, used for summarization | Executive summary + compiles full report | None |

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

### Layer 5: Skills Library

**Role:** A shared library of callable tools that any agent can invoke at runtime to fetch live, external data.

This is the layer that makes agents genuinely autonomous rather than just reasoning pipelines. Without skills, agents can only reason over data that was passed into them. With skills, agents can actively go look things up mid-investigation, the same way a real analyst opens VirusTotal or Shodan in a browser.

**The difference in practice:**

```
Without skills:
  "Based on what Threat Intel already found, I think this IP is suspicious."

With skills:
  "Let me check VirusTotal for 203.0.113.42 right now..."
  -> 47/92 engines flagged it as malicious
  "Let me check Shodan..."
  -> Port 4444 open, tagged as known C2 server
  "I can now confirm with high confidence this is an active C2."
```

**How skills work technically:**

Each skill is a Python async function wrapped as a Claude tool definition. The agent receives a list of available skill schemas, decides which ones to call, Claude issues a `tool_use` block, the skill executes, and the result is fed back into the conversation before Claude produces its final output.

```
Agent prompt sent to Claude (with skill schemas attached)
        |
        v
Claude decides to call a skill: {"name": "lookup_virustotal", "input": {"ioc": "203.0.113.42"}}
        |
        v
Backend executes the skill function -> calls VirusTotal API
        |
        v
Result injected back into Claude's context as a tool_result
        |
        v
Claude continues reasoning with real, live data
        |
        v
Claude calls the submit_* tool to return its final structured output
```

**Available skills and which agents use them:**

| Skill | External API | What It Returns | Used By |
|---|---|---|---|
| `rag_search(query)` | Pinecone (internal) | Relevant MITRE TTPs, CVEs, KEV entries from vector store | Triage, Threat Intel, Investigation |
| `lookup_virustotal(ioc)` | VirusTotal API | Detection ratio, reputation score, tags for an IP/domain/hash | Threat Intel, Investigation |
| `check_cisa_kev(cve_id)` | CISA KEV catalog | Whether a CVE is actively exploited in the wild | Threat Intel, Remediation |
| `get_cve_details(cve_id)` | NIST NVD API | CVSS score, description, affected products, patch info | Threat Intel, Remediation |
| `get_host_info(ip)` | Shodan API | Open ports, running services, banners, tags (C2, scanner, etc.) | Investigation |
| `geolocate_ip(ip)` | ip-api.com (free) | Country, ASN, organization, known malicious network flags | Investigation |

**Why this is a clean abstraction:**

All skill functions live in `backend/app/skills/` and are completely decoupled from agent logic. An agent only sees the tool schema. The actual API call, error handling, rate limiting, and response parsing happen inside the skill. This means:

- Skills are independently testable
- You can swap a skill's underlying API without touching any agent
- New agents can pick up existing skills without duplication
- Skills can be mocked in tests for fast, deterministic CI

---

### Layer 6: RAG Pipeline (LangChain + Pinecone)

**Role:** Give agents access to a searchable knowledge base of threat intelligence, exposed as the `rag_search` skill.

**What RAG is:** Retrieval Augmented Generation. Instead of relying purely on Claude's training data (which may be outdated or lack specifics), we give the model a knowledge base to look things up in, like an open-book exam.

**How it works:**

```
Agent calls rag_search("PowerShell encoded command MITRE T1059")
        |
        v
Query is converted to a vector (Voyage-3 embedding model)
        |
        v
Pinecone finds the 5 most semantically similar chunks in the index
        |
        v
Chunks returned: 2 MITRE TTPs, 1 CISA KEV entry, 1 CVE, 1 threat report excerpt
        |
        v
Those chunks are injected back into Claude's context as a tool_result
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

### Layer 7: Data Persistence (PostgreSQL)

**Role:** Store all structured data (alerts, agent outputs, incident reports) durably and queryably.

The project uses two storage systems for two different jobs:

| Store | What It Holds | Why |
|---|---|---|
| **PostgreSQL** | Alerts, incident reports, agent output history | Structured, relational, queryable with SQL |
| **Pinecone** | Threat intelligence embeddings | Optimized purely for vector similarity search |

PostgreSQL uses the **pgvector** extension, which adds native vector search support. This means you could consolidate both into PostgreSQL later if you want to eliminate Pinecone as a dependency. We use the Docker image `pgvector/pgvector:pg16` which ships with the extension pre-installed.

---

### Layer 8: Observability (LangSmith)

**Role:** Record, trace, debug, and evaluate every LLM call and skill invocation the system makes.

In a normal application you can add print statements and read logs. With multi-agent LLM systems, failures are subtler. An agent might produce a plausible-looking but wrong answer, or call the wrong skill, or misinterpret a skill result. LangSmith solves this.

**What LangSmith captures per agent run:**

```
Without LangSmith:                  With LangSmith:
"Why did triage give the            Full trace showing:
 wrong severity?"          ->       +-- Exact system prompt sent
                                    +-- Which skills were called and why
                                    +-- Raw skill results returned
                                    +-- Exact Claude response
                                    +-- Token count + latency per step
                                    +-- Where in the graph it went wrong
```

**Evals:** LangSmith also enables automated evaluation. You can define test cases (e.g., "this known-bad alert must score at least HIGH") and run them on a schedule to catch regressions as you iterate on prompts or add new skills.

This is what separates an AI prototype from a production system. You can measure and prove your agents are performing correctly.

---

### Layer 9: Dashboard (Next.js)

**Role:** The analyst-facing interface for the entire platform.

Built with Next.js + Tailwind CSS + shadcn/ui. Key views:

- **Alert feed:** live list of incoming alerts with severity badges and pipeline status
- **Agent activity panel:** shows which agents have fired, which skills were called, and their outputs in real time
- **Incident report view:** full structured report with triage, threat intel, investigation, remediation, and executive summary
- **Analyst chat:** natural language interface to query alerts ("show me all critical alerts from the last 24 hours involving lateral movement")

---

## Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| **LLM** | Anthropic Claude (Opus / Sonnet / Haiku) | Core reasoning for all agents |
| **Agent Orchestration** | LangGraph | Stateful multi-agent graph |
| **Skills: IOC Reputation** | VirusTotal API | Live malware and IP reputation lookups |
| **Skills: Host Intel** | Shodan API | Open ports, services, C2 tagging |
| **Skills: IP Geolocation** | ip-api.com | Free IP geolocation and ASN data |
| **Skills: Vulnerability** | NIST NVD API + CISA KEV | Live CVE details and exploitation status |
| **RAG** | LangChain + Pinecone | Threat intel retrieval pipeline |
| **Embeddings** | Voyage-3 (Anthropic) | Text to vector conversion |
| **Observability** | LangSmith | LLM tracing, skill tracing, evals |
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
|   |   |   +-- threat_intel.py    # RAG + live skill enrichment
|   |   |   +-- investigation.py   # Attack chain reconstruction
|   |   |   +-- remediation.py     # Playbook generation
|   |   |   +-- reporting.py       # Incident report compilation
|   |   +-- skills/
|   |   |   +-- __init__.py        # Skill registry: maps names to functions + schemas
|   |   |   +-- virustotal.py      # lookup_virustotal(ioc) -> reputation data
|   |   |   +-- shodan.py          # get_host_info(ip) -> ports, services, tags
|   |   |   +-- nvd.py             # get_cve_details(cve_id) -> CVSS, patches
|   |   |   +-- cisa_kev.py        # check_cisa_kev(cve_id) -> exploitation status
|   |   |   +-- ip_intel.py        # geolocate_ip(ip) -> country, ASN, org
|   |   |   +-- rag_search.py      # rag_search(query) -> vector store results
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
|   |   +-- skills/                # Unit tests for each skill (mockable)
|   |   +-- agents/                # Agent integration tests
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
- API keys: Anthropic, Pinecone, LangSmith, VirusTotal, Shodan (all have free tiers)

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

## Roadmap

- [ ] Week 1: Infrastructure setup + threat intel ingestion pipeline
- [ ] Week 2: Triage + Threat Intel agents + Skills Library (VirusTotal, CISA KEV, NVD, RAG)
- [ ] Week 3: Investigation + Remediation + Reporting agents + remaining skills (Shodan, IP geolocation)
- [ ] Week 4: Next.js dashboard + LangSmith evals + Docker polish

---

## Skills Demonstrated

| Skill | Where |
|---|---|
| Multi-agent orchestration | LangGraph supervisor + conditional routing |
| Agentic tool use | Skills library called dynamically by agents at runtime |
| RAG pipelines | LangChain + Pinecone + Voyage-3 embeddings |
| Structured LLM output | Every agent uses forced tool calling for typed, parseable responses |
| Model tiering | Opus / Sonnet / Haiku matched to task complexity |
| Async backend engineering | FastAPI + Celery + Redis |
| LLM observability + evals | LangSmith tracing on every agent call and skill invocation |
| Production containerization | Docker Compose with health checks |
| CI/CD | GitHub Actions lint + test on every push |
| Cyber domain expertise | MITRE ATT&CK, CVE/NVD, CISA KEV, VirusTotal, Shodan, real IOC patterns |

---

Built with [Claude](https://anthropic.com) + [LangGraph](https://langchain-ai.github.io/langgraph/)
