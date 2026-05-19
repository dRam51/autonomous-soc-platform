"""
IP Intelligence Skill
Geolocates an IP address and returns country, ASN, organization,
and flags for known-bad network characteristics.
Uses ip-api.com which is free with no API key required.
"""

import httpx
import logging

logger = logging.getLogger(__name__)

IP_INTEL_SCHEMA = {
    "name": "geolocate_ip",
    "description": (
        "Geolocate an IP address and retrieve its country, ASN, hosting organization, "
        "and flags indicating whether it is associated with a proxy, VPN, Tor, or datacenter."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "ip": {
                "type": "string",
                "description": "The IP address to geolocate and analyze",
            }
        },
        "required": ["ip"],
    },
}

IP_API_BASE = "http://ip-api.com/json"
FIELDS = "status,message,country,countryCode,region,city,isp,org,as,proxy,hosting,query"

# Known high-risk countries for context (not definitive, just informational)
HIGH_RISK_COUNTRY_CODES = {
    "CN", "RU", "KP", "IR", "BY", "SY"
}


async def geolocate_ip(ip: str) -> str:
    """Geolocate an IP and return a formatted intelligence summary."""
    url = f"{IP_API_BASE}/{ip}"
    params = {"fields": FIELDS}

    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(url, params=params)

    if resp.status_code != 200:
        return f"IP Intel: Request failed with status {resp.status_code} for IP '{ip}'."

    data = resp.json()

    if data.get("status") == "fail":
        return f"IP Intel: Could not resolve IP '{ip}' - {data.get('message', 'unknown error')}."

    country = data.get("country", "Unknown")
    country_code = data.get("countryCode", "")
    city = data.get("city", "Unknown")
    isp = data.get("isp", "Unknown")
    org = data.get("org", "Unknown")
    asn = data.get("as", "Unknown")
    is_proxy = data.get("proxy", False)
    is_hosting = data.get("hosting", False)

    risk_flags = []
    if is_proxy:
        risk_flags.append("proxy/VPN")
    if is_hosting:
        risk_flags.append("datacenter/hosting")
    if country_code in HIGH_RISK_COUNTRY_CODES:
        risk_flags.append(f"high-risk country ({country_code})")

    risk_level = "HIGH" if len(risk_flags) >= 2 else "MEDIUM" if risk_flags else "LOW"

    return (
        f"IP Intelligence for '{ip}':\n"
        f"  Risk level: {risk_level}\n"
        f"  Location: {city}, {country} ({country_code})\n"
        f"  ISP: {isp}\n"
        f"  Organization: {org}\n"
        f"  ASN: {asn}\n"
        f"  Risk flags: {', '.join(risk_flags) if risk_flags else 'none detected'}"
    )
