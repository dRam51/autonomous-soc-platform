"""
Vector Store — Pinecone client for RAG over threat intelligence corpus.
Indexes: MITRE ATT&CK, CVE/NVD, CISA KEV
"""

from pinecone import Pinecone
from langchain_anthropic import ChatAnthropic
from langchain_pinecone import PineconeVectorStore
from langchain.embeddings import OpenAIEmbeddings
from app.config import settings
import logging

logger = logging.getLogger(__name__)

_pinecone_client: Pinecone | None = None
_vector_store: PineconeVectorStore | None = None


def get_pinecone_client() -> Pinecone:
    global _pinecone_client
    if _pinecone_client is None:
        _pinecone_client = Pinecone(api_key=settings.pinecone_api_key)
    return _pinecone_client


def get_vector_store() -> PineconeVectorStore:
    """Returns a LangChain-wrapped Pinecone vector store."""
    global _vector_store
    if _vector_store is None:
        pc = get_pinecone_client()
        index = pc.Index(settings.pinecone_index_name)
        # Using Anthropic embeddings via voyage-3 (Anthropic's embedding model)
        # or swap for OpenAI text-embedding-3-large
        from langchain_community.embeddings import VoyageEmbeddings
        embeddings = VoyageEmbeddings(voyage_api_key=settings.anthropic_api_key, model="voyage-3")
        _vector_store = PineconeVectorStore(index=index, embedding=embeddings)
    return _vector_store


async def query_threat_intel(query: str, top_k: int = 5) -> str:
    """
    RAG query: retrieve relevant threat intel chunks for a given query.
    Returns formatted context string for the LLM.
    """
    try:
        vs = get_vector_store()
        docs = vs.similarity_search(query, k=top_k)

        if not docs:
            return "No relevant threat intelligence found in the knowledge base."

        context_parts = []
        for i, doc in enumerate(docs, 1):
            source = doc.metadata.get("source", "Unknown")
            context_parts.append(f"[{i}] Source: {source}\n{doc.page_content}")

        return "\n\n".join(context_parts)

    except Exception as e:
        logger.error(f"Vector store query failed: {e}")
        return "Threat intelligence retrieval temporarily unavailable."
