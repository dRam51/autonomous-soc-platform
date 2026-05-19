"""
NVD Skill
Fetches live CVE details from the NIST National Vulnerability Database:
CVSS score, severity, description, affected products, and patch availability.
"""

import httpx
from app.config import settings
import logging

logger = logging.getLogger(__name__)

NVD_SCHEMA = {
    "name": "get_cve_details",
    "description": (
        "Fetch detailed information about a CVE from the NIST National Vulnerability Database, "
        "including CVSS score, severity rating, affected products, and patch status."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "cve_id": {
                "type": "string",
                "description": "The CVE identifier, e.g. CVE-2021-44228",
            }
        },
        "required": ["cve_id"],
    },
}

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


async def get_cve_details(cve_id: str) -> str:
    """Fetch CVE details from NIST NVD."""
    params = {"cveId": cve_id}
    headers = {}
    if settings.nvd_api_key:
        headers["apiKey"] = settings.nvd_api_key

    async with httpx.AsyncClient(timeout=20) as client:
        resp = await client.get(NVD_BASE, params=params, headers=headers)

    if resp.status_code != 200:
        return f"NVD: Request failed with status {resp.status_code} for {cve_id}."

    vulns = resp.json().get("vulnerabilities", [])
    if not vulns:
        return f"NVD: No data found for {cve_id}."

    cve = vulns[0].get("cve", {})
    descriptions = cve.get("descriptions", [])
    desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "No description available.")

    metrics = cve.get("metrics", {})
    cvss_score = "N/A"
    severity = "UNKNOWN"

    for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if version_key in metrics:
            cvss_data = metrics[version_key][0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore", "N/A")
            severity = cvss_data.get("baseSeverity", metrics[version_key][0].get("baseSeverity", "UNKNOWN"))
            break

    published = cve.get("published", "Unknown")[:10]
    status = cve.get("vulnStatus", "Unknown")

    references = [r.get("url", "") for r in cve.get("references", [])[:3]]

    return (
        f"NVD details for {cve_id}:\n"
        f"  CVSS Score: {cvss_score} ({severity})\n"
        f"  Status: {status}\n"
        f"  Published: {published}\n"
        f"  Description: {desc[:400]}\n"
        f"  References: {', '.join(references) if references else 'none'}"
    )
