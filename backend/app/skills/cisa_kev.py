"""
CISA KEV Skill
Checks whether a CVE appears in CISA's Known Exploited Vulnerabilities catalog,
meaning it has been actively exploited in the wild and requires immediate attention.
The KEV catalog is fetched and cached in memory for 24 hours.
"""

import httpx
import asyncio
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

CISA_KEV_SCHEMA = {
    "name": "check_cisa_kev",
    "description": (
        "Check if a CVE ID appears in the CISA Known Exploited Vulnerabilities (KEV) catalog. "
        "KEV entries represent vulnerabilities actively exploited in real-world attacks and "
        "require immediate remediation per CISA guidance."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "cve_id": {
                "type": "string",
                "description": "The CVE identifier to check, e.g. CVE-2021-44228",
            }
        },
        "required": ["cve_id"],
    },
}

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# In-memory cache
_kev_cache: dict = {}
_kev_cache_time: datetime | None = None
_kev_lock = asyncio.Lock()
CACHE_TTL = timedelta(hours=24)


async def _get_kev_catalog() -> dict:
    """Fetch and cache the KEV catalog. Thread-safe with asyncio lock."""
    global _kev_cache, _kev_cache_time

    async with _kev_lock:
        if _kev_cache and _kev_cache_time and datetime.utcnow() - _kev_cache_time < CACHE_TTL:
            return _kev_cache

        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(CISA_KEV_URL)
            resp.raise_for_status()
            data = resp.json()

        _kev_cache = {v["cveID"]: v for v in data.get("vulnerabilities", [])}
        _kev_cache_time = datetime.utcnow()
        logger.info(f"[CISA KEV] Loaded {len(_kev_cache)} entries into cache")
        return _kev_cache


async def check_cisa_kev(cve_id: str) -> str:
    """Check if a CVE is in the CISA KEV catalog."""
    cve_id = cve_id.upper().strip()

    try:
        catalog = await _get_kev_catalog()
    except Exception as e:
        return f"CISA KEV: Could not fetch catalog ({e}). Cannot verify exploitation status."

    if cve_id not in catalog:
        return (
            f"CISA KEV: {cve_id} is NOT in the Known Exploited Vulnerabilities catalog. "
            f"No confirmed active exploitation on record."
        )

    entry = catalog[cve_id]
    return (
        f"CISA KEV: {cve_id} IS in the Known Exploited Vulnerabilities catalog.\n"
        f"  Vendor/Product: {entry.get('vendorProject', 'Unknown')} - {entry.get('product', 'Unknown')}\n"
        f"  Vulnerability name: {entry.get('vulnerabilityName', 'Unknown')}\n"
        f"  Description: {entry.get('shortDescription', 'N/A')[:300]}\n"
        f"  Required action: {entry.get('requiredAction', 'N/A')}\n"
        f"  CISA due date: {entry.get('dueDate', 'N/A')}\n"
        f"  Known ransomware use: {entry.get('knownRansomwareCampaignUse', 'Unknown')}"
    )
