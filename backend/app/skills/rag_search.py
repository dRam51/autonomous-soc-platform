"""
RAG Search Skill
Semantic search over the Pinecone threat intelligence corpus.
This is the skills-layer wrapper around the core vector_store module,
making it callable as a Claude tool by any agent.

RAG (Retrieval-Augmented Generation): before the LLM answers, relevant documents
are fetched from a vector store and included in the prompt. This grounds the model
in real threat intel (MITRE ATT&CK descriptions, CISA KEV entries, NVD CVE data)
rather than pattern-matched generalizations from training data. When the model
looks up T1059.001, it reads the actual MITRE ATT&CK technique description rather
than recalling a potentially stale or imprecise training-time approximation.
"""

from app.core.vector_store import query_threat_intel
import logging

logger = logging.getLogger(__name__)

# The schema description gives detailed query examples. This matters because the
# model's query quality directly determines retrieval quality. A vague query like
# "PowerShell" returns generic results; a specific query like "PowerShell encoded
# command execution T1059" retrieves the exact MITRE technique entry.
RAG_SEARCH_SCHEMA = {
    "name": "rag_search",
    "description": (
        "Search the threat intelligence knowledge base for relevant information. "
        "The knowledge base contains MITRE ATT&CK techniques, CISA Known Exploited "
        "Vulnerabilities, and NIST NVD CVE entries. Use this to find TTPs, threat actor "
        "context, CVE details, or any security concept relevant to the current alert."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": (
                    "Natural language search query. Be specific for better results. "
                    "Examples: 'PowerShell encoded command execution T1059', "
                    "'CVE-2021-44228 Log4Shell exploitation', "
                    "'lateral movement via SMB credential reuse'"
                ),
            },
            "top_k": {
                "type": "integer",
                "description": "Number of results to return (default 5, max 10)",
                "default": 5,
            },
        },
        "required": ["query"],
    },
}


async def rag_search(query: str, top_k: int = 5) -> str:
    """Search the threat intelligence vector store and return formatted results.

    The cap at top_k=10 prevents the model from requesting excessively large
    context chunks. Each retrieved document occupies tokens in the conversation;
    beyond ~10 results, the marginal value of additional context drops while
    the token cost and risk of context dilution both increase.
    """
    top_k = min(top_k, 10)
    logger.info(f"[RAG Search] Query: '{query[:80]}...' (top_k={top_k})")
    result = await query_threat_intel(query, top_k=top_k)
    return result
