"""
Shodan Skill
Retrieves host intelligence for an IP address: open ports, running services,
banners, and threat tags (C2, scanner, etc.).
"""

import httpx
from app.config import settings
import logging

logger = logging.getLogger(__name__)

# The schema description directly maps to what a SOC analyst would want to know
# about a suspicious IP: is it a known C2, what services is it running, has Shodan
# flagged it as a scanner? Detailed descriptions guide the model to use this skill
# for infrastructure investigation rather than IOC reputation checks (that's VT).
SHODAN_SCHEMA = {
    "name": "get_host_info",
    "description": (
        "Look up an IP address in Shodan to get open ports, running services, "
        "software banners, and threat tags such as C2, scanner, or tor-exit."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "ip": {
                "type": "string",
                "description": "The IP address to look up in Shodan",
            }
        },
        "required": ["ip"],
    },
}

SHODAN_BASE = "https://api.shodan.io"


async def get_host_info(ip: str) -> str:
    """Query Shodan for host intelligence on an IP address.

    Shodan's data differs from VirusTotal: instead of asking "is this IP malicious?",
    Shodan tells you "what is running on this IP right now?" An attacker's C2 server
    might be unknown to VT but clearly identifiable by Shodan's open-port data and
    tags (e.g., tagged "c2" by Shodan's honeypot correlation engine).
    """
    if not settings.shodan_api_key:
        return "Shodan API key not configured. Skipping host intelligence lookup."

    url = f"{SHODAN_BASE}/shodan/host/{ip}"
    params = {"key": settings.shodan_api_key}

    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(url, params=params)

    if resp.status_code == 404:
        return f"Shodan: No data found for IP '{ip}'."
    if resp.status_code == 401:
        return "Shodan: Invalid API key."
    if resp.status_code != 200:
        return f"Shodan: Request failed with status {resp.status_code}."

    data = resp.json()
    ports = data.get("ports", [])
    country = data.get("country_name", "Unknown")
    org = data.get("org", "Unknown")
    hostnames = data.get("hostnames", [])
    tags = data.get("tags", [])
    # Shodan's vuln field contains CVEs detected from banner fingerprinting.
    # These are not confirmed exploitations but known vulnerabilities on visible services.
    vulns = list(data.get("vulns", {}).keys())

    # Limit to 5 services to keep the result concise enough for the model's context.
    # The investigation agent needs to process results from multiple IPs, so verbosity here
    # would dilute the signal.
    services = []
    for item in data.get("data", [])[:5]:
        port = item.get("port", "")
        transport = item.get("transport", "tcp")
        product = item.get("product", "")
        version = item.get("version", "")
        svc = f"{port}/{transport}"
        if product:
            svc += f" ({product} {version})".rstrip()
        services.append(svc)

    # Shodan tags like "c2", "malware", "scanner", "tor" come from Shodan's own
    # threat intelligence correlation. These are high-signal indicators that the
    # model should treat as strong evidence in its investigation.
    threat_level = "HIGH" if any(t in tags for t in ["c2", "malware", "scanner", "tor"]) else "UNKNOWN"

    return (
        f"Shodan host intelligence for IP '{ip}':\n"
        f"  Threat level: {threat_level}\n"
        f"  Organization: {org}\n"
        f"  Country: {country}\n"
        f"  Hostnames: {', '.join(hostnames[:3]) if hostnames else 'none'}\n"
        f"  Open ports: {', '.join(str(p) for p in ports[:10])}\n"
        f"  Services: {', '.join(services) if services else 'none detected'}\n"
        f"  Tags: {', '.join(tags) if tags else 'none'}\n"
        f"  Known vulnerabilities: {', '.join(vulns[:5]) if vulns else 'none listed'}"
    )
