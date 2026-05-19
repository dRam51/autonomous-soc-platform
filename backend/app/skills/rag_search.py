"""
RAG Search Skill
Semantic search over the Pinecone threat intelligence corpus.
This is the skills-layer wrapper around the core vector_store module,
making it callable as a Claude tool by any agent.
"""

from app.core.vector_store import query_threat_intel
import logging

logger = logging.getLogger(__name__)

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
    """Search the threat intelligence vector store and return formatted results."""
    top_k = min(top_k, 10)
    logger.info(f"[RAG Search] Query: '{query[:80]}...' (top_k={top_k})")
    result = await query_threat_intel(query, top_k=top_k)
    return result
