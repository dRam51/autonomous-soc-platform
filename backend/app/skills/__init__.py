"""
Skills Registry
Maps skill names to their async handler functions and Claude tool schemas.
Agents import SKILL_REGISTRY to get the schemas for their tool list,
then call dispatch_skill() when Claude issues a tool_use block.

Design rationale: each agent declares which skills it needs by name. This
registry pattern means adding a new skill (e.g., Recorded Future, Crowdstrike)
requires only two changes: add it here and write the handler module. No agent
code needs to change. It also makes testing easy: you can mock dispatch_skill
to inject canned responses without touching any agent logic.
"""

from app.skills.virustotal import lookup_virustotal, VIRUSTOTAL_SCHEMA
from app.skills.shodan import get_host_info, SHODAN_SCHEMA
from app.skills.nvd import get_cve_details, NVD_SCHEMA
from app.skills.cisa_kev import check_cisa_kev, CISA_KEV_SCHEMA
from app.skills.ip_intel import geolocate_ip, IP_INTEL_SCHEMA
from app.skills.rag_search import rag_search, RAG_SEARCH_SCHEMA

# Each entry is (async_handler, claude_tool_schema). The schema tells Claude what
# inputs the skill accepts. The handler executes the skill and returns a plain string
# that gets injected back into Claude's conversation as a tool_result.
SKILL_REGISTRY = {
    "lookup_virustotal": (lookup_virustotal, VIRUSTOTAL_SCHEMA),
    "get_host_info":     (get_host_info,     SHODAN_SCHEMA),
    "get_cve_details":   (get_cve_details,   NVD_SCHEMA),
    "check_cisa_kev":    (check_cisa_kev,    CISA_KEV_SCHEMA),
    "geolocate_ip":      (geolocate_ip,      IP_INTEL_SCHEMA),
    "rag_search":        (rag_search,        RAG_SEARCH_SCHEMA),
}


def get_skill_schemas(names: list[str]) -> list[dict]:
    """Return the Claude tool schemas for the requested skill names.

    Each agent calls this to build its tools list before each API call.
    Agents only receive schemas for skills they are authorized to use,
    which keeps the tool list short and the model focused on relevant actions.
    """
    return [SKILL_REGISTRY[n][1] for n in names if n in SKILL_REGISTRY]


async def dispatch_skill(name: str, inputs: dict) -> str:
    """
    Execute a skill by name with the given inputs.
    Returns a plain-text result string to feed back into Claude as a tool_result.

    All errors are caught and returned as readable strings rather than exceptions.
    This is intentional: the agent receives the error in context and can adapt
    (try a different tool, skip the lookup, note the limitation in its output).
    Raising an exception here would crash the entire pipeline for an API outage.
    """
    if name not in SKILL_REGISTRY:
        return f"Unknown skill: {name}"
    handler, _ = SKILL_REGISTRY[name]
    try:
        return await handler(**inputs)
    except Exception as e:
        return f"Skill {name} failed: {str(e)}"
