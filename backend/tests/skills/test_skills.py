"""
Skills Unit Tests

Each skill is independently testable by mocking the external HTTP call.
This validates that skills correctly parse API responses and handle errors
without requiring real API keys in CI.
"""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from app.skills.virustotal import lookup_virustotal
from app.skills.ip_intel import geolocate_ip
from app.skills.cisa_kev import check_cisa_kev, _kev_cache, _kev_cache_time
from app.skills.nvd import get_cve_details
from app.skills import dispatch_skill, get_skill_schemas, SKILL_REGISTRY


# ─── Skill Registry Tests ─────────────────────────────────────────────────────

def test_skill_registry_has_all_skills():
    expected = {"lookup_virustotal", "get_host_info", "get_cve_details",
                "check_cisa_kev", "geolocate_ip", "rag_search"}
    assert set(SKILL_REGISTRY.keys()) == expected


def test_get_skill_schemas_returns_correct_subset():
    schemas = get_skill_schemas(["lookup_virustotal", "rag_search"])
    names = {s["name"] for s in schemas}
    assert names == {"lookup_virustotal", "rag_search"}


def test_get_skill_schemas_ignores_unknown():
    schemas = get_skill_schemas(["lookup_virustotal", "nonexistent_skill"])
    assert len(schemas) == 1


# ─── VirusTotal Tests ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_virustotal_malicious_ip(monkeypatch):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 47, "suspicious": 3, "clean": 42},
                "reputation": -75,
                "tags": ["c2", "malware"],
                "country": "RU",
            }
        }
    }

    with patch("httpx.AsyncClient") as mock_client:
        mock_client.return_value.__aenter__.return_value.get = AsyncMock(return_value=mock_response)
        result = await lookup_virustotal("203.0.113.42", "ip")

    assert "MALICIOUS" in result
    assert "47" in result
    assert "c2" in result


@pytest.mark.asyncio
async def test_virustotal_not_found(monkeypatch):
    mock_response = MagicMock()
    mock_response.status_code = 404

    with patch("httpx.AsyncClient") as mock_client:
        mock_client.return_value.__aenter__.return_value.get = AsyncMock(return_value=mock_response)
        result = await lookup_virustotal("192.168.1.1", "ip")

    assert "No data found" in result


@pytest.mark.asyncio
async def test_virustotal_no_api_key(monkeypatch):
    monkeypatch.setattr("app.skills.virustotal.settings.virustotal_api_key", "")
    result = await lookup_virustotal("1.2.3.4", "ip")
    assert "not configured" in result.lower()


# ─── IP Intelligence Tests ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_geolocate_ip_high_risk():
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "status": "success",
        "country": "Russia",
        "countryCode": "RU",
        "city": "Moscow",
        "isp": "Rostelecom",
        "org": "AS12389",
        "as": "AS12389 Rostelecom",
        "proxy": True,
        "hosting": False,
        "query": "1.2.3.4",
    }

    with patch("httpx.AsyncClient") as mock_client:
        mock_client.return_value.__aenter__.return_value.get = AsyncMock(return_value=mock_response)
        result = await geolocate_ip("1.2.3.4")

    assert "HIGH" in result
    assert "Russia" in result
    assert "proxy/VPN" in result


# ─── CISA KEV Tests ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_cisa_kev_found(monkeypatch):
    import app.skills.cisa_kev as kev_module
    kev_module._kev_cache = {
        "CVE-2021-44228": {
            "cveID": "CVE-2021-44228",
            "vendorProject": "Apache",
            "product": "Log4j2",
            "vulnerabilityName": "Apache Log4j2 Remote Code Execution",
            "shortDescription": "Log4Shell RCE vulnerability",
            "requiredAction": "Apply updates per vendor instructions",
            "dueDate": "2021-12-24",
            "knownRansomwareCampaignUse": "Known",
        }
    }
    from datetime import datetime
    kev_module._kev_cache_time = datetime.utcnow()

    result = await check_cisa_kev("CVE-2021-44228")
    assert "IS in the Known Exploited" in result
    assert "Log4j2" in result
    assert "Known" in result


@pytest.mark.asyncio
async def test_cisa_kev_not_found(monkeypatch):
    import app.skills.cisa_kev as kev_module
    kev_module._kev_cache = {}
    from datetime import datetime
    kev_module._kev_cache_time = datetime.utcnow()

    result = await check_cisa_kev("CVE-9999-99999")
    assert "NOT in" in result


# ─── NVD Tests ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_cve_details_success():
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2021-44228",
                "descriptions": [{"lang": "en", "value": "Apache Log4j2 RCE vulnerability"}],
                "metrics": {
                    "cvssMetricV31": [{
                        "cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL"}
                    }]
                },
                "published": "2021-12-10T00:00:00.000Z",
                "vulnStatus": "Analyzed",
                "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"}],
            }
        }]
    }

    with patch("httpx.AsyncClient") as mock_client:
        mock_client.return_value.__aenter__.return_value.get = AsyncMock(return_value=mock_response)
        result = await get_cve_details("CVE-2021-44228")

    assert "10.0" in result
    assert "CRITICAL" in result
    assert "Log4j2" in result


# ─── Dispatch Tests ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_dispatch_unknown_skill():
    result = await dispatch_skill("nonexistent_skill", {})
    assert "Unknown skill" in result
