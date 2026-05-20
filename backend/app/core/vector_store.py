"""
Vector Store - Pinecone client for RAG over threat intelligence corpus.
Indexes: MITRE ATT&CK, CVE/NVD, CISA KEV

RAG (Retrieval-Augmented Generation) architecture:
  1. At ingestion time (scripts/ingest_threat_intel.py): documents are split into
     chunks, each chunk is converted to a 1024-dimensional embedding by Voyage-3,
     and the (embedding, text, metadata) triplet is upserted into Pinecone.
  2. At query time: the user's query string is embedded with the same model,
     and Pinecone finds the top-k most similar chunks by cosine distance.
  3. The retrieved chunks are returned as context for the LLM prompt.

Why Pinecone for this? Pinecone is a managed vector database that handles ANN
(approximate nearest neighbor) search at scale. The MITRE ATT&CK corpus alone
has 600+ techniques. Linear scan over all embeddings per query would be too slow;
Pinecone's index structure makes retrieval sub-millisecond.
"""

from pinecone import Pinecone
from langchain_anthropic import ChatAnthropic
from langchain_pinecone import PineconeVectorStore
from langchain.embeddings import OpenAIEmbeddings
from app.config import settings
import logging

logger = logging.getLogger(__name__)

# Module-level singletons: the Pinecone client and vector store are expensive
# to initialize (network connection, index metadata fetch). Initializing once
# at startup and reusing across requests is standard practice.
_pinecone_client: Pinecone | None = None
_vector_store: PineconeVectorStore | None = None


def get_pinecone_client() -> Pinecone:
    """Lazy-initialize the Pinecone client. Cached after first call."""
    global _pinecone_client
    if _pinecone_client is None:
        _pinecone_client = Pinecone(api_key=settings.pinecone_api_key)
    return _pinecone_client


def get_vector_store() -> PineconeVectorStore:
    """Returns a LangChain-wrapped Pinecone vector store.

    The embedding model used here MUST be the same one used during ingestion.
    Voyage-3 produces 1024-dim vectors. Switching to a different model without
    re-ingesting would cause the query embedding to live in a different vector
    space than the stored embeddings, making similarity search meaningless.
    """
    global _vector_store
    if _vector_store is None:
        pc = get_pinecone_client()
        index = pc.Index(settings.pinecone_index_name)
        # Voyage-3 is Anthropic's semantic embedding model optimized for retrieval tasks.
        # It encodes text into a 1024-dimensional vector space where semantically similar
        # texts are geometrically close. The voyage_api_key here is the Anthropic key
        # because Voyage is an Anthropic-affiliated embedding service.
        from langchain_community.embeddings import VoyageEmbeddings
        embeddings = VoyageEmbeddings(voyage_api_key=settings.anthropic_api_key, model="voyage-3")
        _vector_store = PineconeVectorStore(index=index, embedding=embeddings)
    return _vector_store


async def query_threat_intel(query: str, top_k: int = 5) -> str:
    """
    RAG query: retrieve relevant threat intel chunks for a given query.
    Returns formatted context string for the LLM.

    similarity_search embeds the query string, queries Pinecone for the top_k
    nearest vectors by cosine similarity, and returns the associated document text.
    The returned text is then injected into the agent's prompt as grounding context.

    The source metadata field tells the model and analysts which corpus the
    chunk came from (mitre_attack, cisa_kev, nvd), which affects how it should
    be interpreted (TTP description vs. actively exploited CVE vs. NVD score).
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
        # Return a graceful degradation message so the agent can continue without
        # RAG context rather than crashing the entire pipeline.
        return "Threat intelligence retrieval temporarily unavailable."
