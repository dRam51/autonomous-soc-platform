"""
Threat Intelligence Ingestion Script
Fetches and indexes the following sources into Pinecone:
  - MITRE ATT&CK (STIX format)
  - NIST NVD CVE feed (recent CVEs)
  - CISA Known Exploited Vulnerabilities (KEV)

Run once to seed the vector store, then periodically to keep it fresh.
Cron example: 0 2 * * 0   (every Sunday at 2am)

This script populates the RAG corpus that agents query via rag_search.
Without running this, all rag_search calls return "No relevant threat intelligence found."

Usage:
    python scripts/ingest_threat_intel.py
"""

import asyncio
import httpx
import json
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

from pinecone import Pinecone, ServerlessSpec
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.schema import Document

MITRE_ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=100&startIndex=0"

# RecursiveCharacterTextSplitter splits on paragraph, sentence, then word boundaries
# in that order. chunk_size=500 tokens balances retrieval precision (small chunks are
# more targeted) against context sufficiency (chunks must be large enough to be useful).
# chunk_overlap=50 ensures technique descriptions don't get cut mid-sentence at boundaries.
splitter = RecursiveCharacterTextSplitter(chunk_size=500, chunk_overlap=50)


# === Source Fetchers ===

async def fetch_mitre_attack() -> list[Document]:
    """Fetch MITRE ATT&CK techniques from STIX bundle.

    STIX (Structured Threat Information eXpression) is the standard serialization
    format for cyber threat intelligence. The ATT&CK STIX bundle contains all
    techniques as "attack-pattern" objects. We filter to non-revoked techniques
    and extract technique ID, name, description, platforms, and kill chain phases.

    The formatted text per technique is designed so a semantic query like
    "encoding PowerShell commands" retrieves T1059.001 rather than a generic
    PowerShell article.
    """
    print("Fetching MITRE ATT&CK...")
    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.get(MITRE_ATTACK_URL)
        data = resp.json()

    docs = []
    for obj in data.get("objects", []):
        # Filter to attack-pattern objects (techniques/sub-techniques) and
        # exclude revoked techniques that MITRE has deprecated.
        if obj.get("type") == "attack-pattern" and not obj.get("revoked"):
            technique_id = ""
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id", "")

            # Structure the text so it reads naturally for embedding:
            # the technique ID and name appear early (high weight in embedding),
            # with description providing semantic richness for fuzzy matching.
            text = f"""MITRE ATT&CK Technique: {technique_id}
Name: {obj.get('name', '')}
Description: {obj.get('description', '')[:800]}
Platforms: {', '.join(obj.get('x_mitre_platforms', []))}
Kill Chain Phases: {', '.join([p['phase_name'] for p in obj.get('kill_chain_phases', [])])}"""

            docs.append(Document(
                page_content=text,
                metadata={"source": "mitre_attack", "technique_id": technique_id, "type": "ttp"}
            ))

    print(f"  -> {len(docs)} ATT&CK techniques loaded")
    return docs


async def fetch_cisa_kev() -> list[Document]:
    """Fetch CISA Known Exploited Vulnerabilities catalog.

    KEV entries are simpler than MITRE techniques: each is a CVE with vendor/product,
    a short description, required CISA action, and due date. Including "Known Ransomware
    Campaign Use" in the text means a query about ransomware will surface KEV entries
    where that field is populated.
    """
    print("Fetching CISA KEV...")
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(CISA_KEV_URL)
        data = resp.json()

    docs = []
    for vuln in data.get("vulnerabilities", []):
        text = f"""CISA Known Exploited Vulnerability
CVE ID: {vuln.get('cveID', '')}
Vendor/Product: {vuln.get('vendorProject', '')} - {vuln.get('product', '')}
Vulnerability Name: {vuln.get('vulnerabilityName', '')}
Description: {vuln.get('shortDescription', '')}
Required Action: {vuln.get('requiredAction', '')}
Due Date: {vuln.get('dueDate', '')}
Known Ransomware Use: {vuln.get('knownRansomwareCampaignUse', 'Unknown')}"""

        docs.append(Document(
            page_content=text,
            metadata={"source": "cisa_kev", "cve_id": vuln.get("cveID", ""), "type": "cve"}
        ))

    print(f"  -> {len(docs)} CISA KEV entries loaded")
    return docs


async def fetch_nvd_cves() -> list[Document]:
    """Fetch recent CVEs from NVD.

    This fetches the first 100 CVEs sorted by NVD's default (most recently modified).
    For a production corpus you would paginate through all CVEs or use a time-range
    filter (pubStartDate/pubEndDate) to ingest only new entries since the last run.
    """
    print("Fetching NVD CVEs...")
    headers = {}
    nvd_key = os.getenv("NVD_API_KEY", "")
    if nvd_key:
        headers["apiKey"] = nvd_key

    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(NVD_CVE_URL, headers=headers)
        data = resp.json()

    docs = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        descriptions = cve.get("descriptions", [])
        desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "")
        metrics = cve.get("metrics", {})
        cvss_score = ""
        if "cvssMetricV31" in metrics:
            cvss_score = metrics["cvssMetricV31"][0]["cvssData"].get("baseScore", "")

        text = f"""NVD CVE Entry
CVE ID: {cve_id}
CVSS Score: {cvss_score}
Description: {desc[:600]}"""

        docs.append(Document(
            page_content=text,
            metadata={"source": "nvd", "cve_id": cve_id, "type": "cve"}
        ))

    print(f"  -> {len(docs)} NVD CVEs loaded")
    return docs


# === Main Ingestion Pipeline ===

async def main():
    from app.core.vector_store import get_pinecone_client
    from langchain_community.embeddings import VoyageEmbeddings
    from langchain_pinecone import PineconeVectorStore

    pinecone_key = os.getenv("PINECONE_API_KEY")
    index_name = os.getenv("PINECONE_INDEX_NAME", "soc-platform")

    pc = Pinecone(api_key=pinecone_key)

    # Create the Pinecone index if it does not already exist.
    # dimension=1024 matches voyage-3's output dimension. Using a different dimension
    # than the embedding model produces would cause upserts to fail.
    # metric="cosine" must match how you query: cosine similarity for semantic search.
    if index_name not in [i.name for i in pc.list_indexes()]:
        print(f"Creating Pinecone index '{index_name}'...")
        pc.create_index(
            name=index_name,
            dimension=1024,  # voyage-3 dimension
            metric="cosine",
            spec=ServerlessSpec(cloud="aws", region="us-east-1"),
        )

    # Fetch all three sources in parallel to minimize total ingestion time.
    # MITRE can take 10-30s (large JSON); fetching concurrently is a significant speedup.
    mitre_docs, kev_docs, nvd_docs = await asyncio.gather(
        fetch_mitre_attack(),
        fetch_cisa_kev(),
        fetch_nvd_cves(),
    )

    # Combine and split: long technique descriptions get chunked into 500-token pieces
    # so each Pinecone vector represents a focused, retrievable unit of knowledge.
    all_docs = mitre_docs + kev_docs + nvd_docs
    chunks = splitter.split_documents(all_docs)
    print(f"\nTotal chunks to index: {len(chunks)}")

    print("Embedding and uploading to Pinecone...")
    # voyage-3 is used for both ingestion and query time - consistency is critical.
    # The ANTHROPIC_API_KEY is the Voyage API key (Voyage is Anthropic-affiliated).
    embeddings = VoyageEmbeddings(
        voyage_api_key=os.getenv("ANTHROPIC_API_KEY"),
        model="voyage-3"
    )

    index = pc.Index(index_name)
    vs = PineconeVectorStore(index=index, embedding=embeddings)

    # Batch upsert in groups of 100 to respect Pinecone's upsert batch size limit
    # and to provide progress feedback. Very large corpora (10k+ chunks) could take
    # several minutes; the progress log confirms the script is still running.
    batch_size = 100
    for i in range(0, len(chunks), batch_size):
        batch = chunks[i:i + batch_size]
        vs.add_documents(batch)
        print(f"  Uploaded batch {i // batch_size + 1}/{(len(chunks) - 1) // batch_size + 1}")

    print("\nThreat intelligence ingestion complete!")


if __name__ == "__main__":
    asyncio.run(main())
