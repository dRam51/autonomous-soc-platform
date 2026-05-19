"""
VirusTotal Skill
Checks IPs, domains, URLs, and file hashes against VirusTotal's threat database.
Returns detection ratio, reputation score, and relevant tags.
"""

import httpx
from app.config import settings
import logging

logger = logging.getLogger(__name__)

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
ENDPOINT_MAP = {
    "ip":     "ip_addresses",
    "domain": "domains",
    "url":    "urls",
    "file":   "files",
}


async def lookup_virustotal(ioc: str, ioc_type: str) -> str:
    """Query VirusTotal for an IOC and return a formatted intelligence summary."""
    if not settings.virustotal_api_key:
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

    verdict = "MALICIOUS" if malicious > 5 else "SUSPICIOUS" if malicious > 0 or suspicious > 2 else "CLEAN"

    return (
        f"VirusTotal results for {ioc_type} '{ioc}':\n"
        f"  Verdict: {verdict}\n"
        f"  Detections: {malicious} malicious, {suspicious} suspicious out of {total} engines\n"
        f"  Reputation score: {reputation}\n"
        f"  Tags: {', '.join(tags) if tags else 'none'}\n"
        f"  Country: {country if country else 'unknown'}"
    )
