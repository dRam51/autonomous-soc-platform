"""
VirusTotal Skill
Checks IPs, domains, URLs, and file hashes against VirusTotal's threat database.
Returns detection ratio, reputation score, and relevant tags.
"""

import httpx
from app.config import settings
import logging

logger = logging.getLogger(__name__)

# The schema is what Claude sees when deciding whether and how to call this skill.
# Descriptive field names and descriptions matter because the model uses them to
# decide what value to pass. "ioc_type" with an enum prevents the model from
# passing unsupported types like "url_encoded" or "hash".
VIRUSTOTAL_SCHEMA = {
    "name": "lookup_virustotal",
    "description": (
        "Look up an indicator of compromise (IP address, domain, URL, or file hash) "
        "in VirusTotal to get its reputation score, detection ratio, and threat tags."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "ioc": {
                "type": "string",
                "description": "The indicator to look up: IP address, domain, URL, or SHA256 hash",
            },
            "ioc_type": {
                "type": "string",
                "enum": ["ip", "domain", "url", "file"],
                "description": "The type of indicator",
            },
        },
        "required": ["ioc", "ioc_type"],
    },
}

VT_BASE = "https://www.virustotal.com/api/v3"

# Maps our ioc_type enum to the VT REST API path segment.
# VT uses different endpoints per IOC type (ip_addresses, domains, urls, files).
ENDPOINT_MAP = {
    "ip":     "ip_addresses",
    "domain": "domains",
    "url":    "urls",
    "file":   "files",
}


async def lookup_virustotal(ioc: str, ioc_type: str) -> str:
    """Query VirusTotal for an IOC and return a formatted intelligence summary.

    Returns a plain string so the result can be directly injected into Claude's
    conversation as a tool_result content block without any serialization.
    """
    if not settings.virustotal_api_key:
        # Graceful degradation: if the key is missing, tell Claude so it can skip
        # this tool and continue with whatever data it has. Returning an error string
        # instead of raising keeps the agentic loop alive.
        return "VirusTotal API key not configured. Skipping IOC lookup."

    endpoint = ENDPOINT_MAP.get(ioc_type, "ip_addresses")
    url = f"{VT_BASE}/{endpoint}/{ioc}"
    headers = {"x-apikey": settings.virustotal_api_key}

    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(url, headers=headers)

    if resp.status_code == 404:
        return f"VirusTotal: No data found for {ioc_type} '{ioc}'."
    if resp.status_code == 401:
        return "VirusTotal: Invalid API key."
    if resp.status_code != 200:
        return f"VirusTotal: Request failed with status {resp.status_code}."

    data = resp.json().get("data", {}).get("attributes", {})
    stats = data.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values()) or 1
    reputation = data.get("reputation", "N/A")
    tags = data.get("tags", [])
    country = data.get("country", "")

    # Simple threshold-based verdict: >5 malicious detections is a strong signal,
    # any malicious or >2 suspicious is worth flagging. This mirrors how a real
    # analyst would read the VT dashboard at a glance.
    verdict = "MALICIOUS" if malicious > 5 else "SUSPICIOUS" if malicious > 0 or suspicious > 2 else "CLEAN"

    return (
        f"VirusTotal results for {ioc_type} '{ioc}':\n"
        f"  Verdict: {verdict}\n"
        f"  Detections: {malicious} malicious, {suspicious} suspicious out of {total} engines\n"
        f"  Reputation score: {reputation}\n"
        f"  Tags: {', '.join(tags) if tags else 'none'}\n"
        f"  Country: {country if country else 'unknown'}"
    )
