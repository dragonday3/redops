"""Tests for MITREClient — all mocked, no real HTTP."""
from __future__ import annotations

import json
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from redops.mitre.client import MITREClient
from redops.models.engagement import Technique


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

FAKE_BUNDLE = {
    "objects": [
        {
            "type": "attack-pattern",
            "name": "Spearphishing Attachment",
            "description": "Adversaries may send spearphishing emails...",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": "T1566.001",
                    "url": "https://attack.mitre.org/techniques/T1566/001",
                }
            ],
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
            ],
            "revoked": False,
        },
        {
            "type": "attack-pattern",
            "name": "Valid Accounts",
            "description": "Adversaries may obtain and abuse credentials...",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": "T1078",
                    "url": "https://attack.mitre.org/techniques/T1078",
                }
            ],
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "defense-evasion"}
            ],
            "revoked": False,
        },
        {
            "type": "attack-pattern",
            "name": "Revoked Technique",
            "description": "Should be filtered out",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T9999", "url": ""}
            ],
            "kill_chain_phases": [],
            "revoked": True,
        },
        {
            "type": "course-of-action",  # should be filtered out
            "name": "Not a technique",
        },
    ]
}


@pytest.fixture
def fake_bundle():
    return FAKE_BUNDLE


def _make_mock_client(bundle: dict) -> AsyncMock:
    """Return a mock httpx.AsyncClient whose .get() returns a fake response."""
    mock_client = AsyncMock()
    mock_response = MagicMock()
    mock_response.json.return_value = bundle
    mock_response.raise_for_status = MagicMock()
    mock_client.get = AsyncMock(return_value=mock_response)
    return mock_client


# ---------------------------------------------------------------------------
# 1. _parse returns only non-revoked attack-patterns (2 from FAKE_BUNDLE)
# ---------------------------------------------------------------------------

def test_parse_returns_two_techniques(fake_bundle):
    techniques = MITREClient._parse(fake_bundle)
    assert len(techniques) == 2


# ---------------------------------------------------------------------------
# 2. _parse extracts technique ID, name, tactic, url correctly
# ---------------------------------------------------------------------------

def test_parse_fields_spearphishing(fake_bundle):
    techniques = MITREClient._parse(fake_bundle)
    t = next(t for t in techniques if t.id == "T1566.001")
    assert t.name == "Spearphishing Attachment"
    assert t.url == "https://attack.mitre.org/techniques/T1566/001"
    assert t.description.startswith("Adversaries may send spearphishing")


def test_parse_fields_valid_accounts(fake_bundle):
    techniques = MITREClient._parse(fake_bundle)
    t = next(t for t in techniques if t.id == "T1078")
    assert t.name == "Valid Accounts"
    assert t.url == "https://attack.mitre.org/techniques/T1078"


# ---------------------------------------------------------------------------
# 3. _parse title-cases tactic name ("initial-access" → "Initial Access")
# ---------------------------------------------------------------------------

def test_parse_tactic_title_case(fake_bundle):
    techniques = MITREClient._parse(fake_bundle)
    t = next(t for t in techniques if t.id == "T1566.001")
    assert t.tactic == "Initial Access"


def test_parse_tactic_defense_evasion(fake_bundle):
    techniques = MITREClient._parse(fake_bundle)
    t = next(t for t in techniques if t.id == "T1078")
    assert t.tactic == "Defense Evasion"


# ---------------------------------------------------------------------------
# 4. _parse filters revoked=True
# ---------------------------------------------------------------------------

def test_parse_filters_revoked(fake_bundle):
    techniques = MITREClient._parse(fake_bundle)
    ids = [t.id for t in techniques]
    assert "T9999" not in ids


# ---------------------------------------------------------------------------
# 5. _parse filters non-attack-pattern objects
# ---------------------------------------------------------------------------

def test_parse_filters_non_attack_pattern(fake_bundle):
    techniques = MITREClient._parse(fake_bundle)
    names = [t.name for t in techniques]
    assert "Not a technique" not in names


# ---------------------------------------------------------------------------
# 6. search by partial name match (case insensitive)
# ---------------------------------------------------------------------------

async def test_search_by_partial_name(tmp_path, fake_bundle):
    cache_file = tmp_path / "mitre_cache.json"
    mock_client = _make_mock_client(fake_bundle)
    client = MITREClient(cache_path=cache_file, http_client=mock_client)

    results = await client.search("spearphishing")
    assert len(results) == 1
    assert results[0].id == "T1566.001"


async def test_search_case_insensitive(tmp_path, fake_bundle):
    cache_file = tmp_path / "mitre_cache.json"
    mock_client = _make_mock_client(fake_bundle)
    client = MITREClient(cache_path=cache_file, http_client=mock_client)

    results = await client.search("VALID ACCOUNTS")
    assert len(results) == 1
    assert results[0].id == "T1078"


# ---------------------------------------------------------------------------
# 7. search by technique ID partial match
# ---------------------------------------------------------------------------

async def test_search_by_id_partial(tmp_path, fake_bundle):
    cache_file = tmp_path / "mitre_cache.json"
    mock_client = _make_mock_client(fake_bundle)
    client = MITREClient(cache_path=cache_file, http_client=mock_client)

    results = await client.search("T1566")
    assert any(t.id == "T1566.001" for t in results)


# ---------------------------------------------------------------------------
# 8. search returns empty list for no match
# ---------------------------------------------------------------------------

async def test_search_no_match(tmp_path, fake_bundle):
    cache_file = tmp_path / "mitre_cache.json"
    mock_client = _make_mock_client(fake_bundle)
    client = MITREClient(cache_path=cache_file, http_client=mock_client)

    results = await client.search("xyzzy_nonexistent_12345")
    assert results == []


# ---------------------------------------------------------------------------
# 9. get by exact ID (case insensitive)
# ---------------------------------------------------------------------------

async def test_get_exact_id_lowercase(tmp_path, fake_bundle):
    cache_file = tmp_path / "mitre_cache.json"
    mock_client = _make_mock_client(fake_bundle)
    client = MITREClient(cache_path=cache_file, http_client=mock_client)

    t = await client.get("t1566.001")
    assert t is not None
    assert t.id == "T1566.001"
    assert t.name == "Spearphishing Attachment"


async def test_get_exact_id_uppercase(tmp_path, fake_bundle):
    cache_file = tmp_path / "mitre_cache.json"
    mock_client = _make_mock_client(fake_bundle)
    client = MITREClient(cache_path=cache_file, http_client=mock_client)

    t = await client.get("T1078")
    assert t is not None
    assert t.name == "Valid Accounts"


# ---------------------------------------------------------------------------
# 10. get returns None for unknown ID
# ---------------------------------------------------------------------------

async def test_get_unknown_id(tmp_path, fake_bundle):
    cache_file = tmp_path / "mitre_cache.json"
    mock_client = _make_mock_client(fake_bundle)
    client = MITREClient(cache_path=cache_file, http_client=mock_client)

    t = await client.get("T9999")
    assert t is None


# ---------------------------------------------------------------------------
# 11. tactics returns sorted list of unique tactic names
# ---------------------------------------------------------------------------

async def test_tactics_sorted_unique(tmp_path, fake_bundle):
    cache_file = tmp_path / "mitre_cache.json"
    mock_client = _make_mock_client(fake_bundle)
    client = MITREClient(cache_path=cache_file, http_client=mock_client)

    result = await client.tactics()
    assert result == sorted(set(result))
    assert "Initial Access" in result
    assert "Defense Evasion" in result
    # Ensure uniqueness — no duplicates
    assert len(result) == len(set(result))


# ---------------------------------------------------------------------------
# 12. Cache hit: file exists + recent → reads file, no HTTP
# ---------------------------------------------------------------------------

async def test_cache_hit(tmp_path, fake_bundle):
    cache_file = tmp_path / "mitre_cache.json"
    # Write a fresh cache file
    cache_file.write_text(json.dumps(fake_bundle), encoding="utf-8")

    mock_client = _make_mock_client(fake_bundle)
    client = MITREClient(cache_path=cache_file, http_client=mock_client)

    techniques = await client._load()
    assert len(techniques) == 2
    # No HTTP call should have been made
    mock_client.get.assert_not_called()


# ---------------------------------------------------------------------------
# 13. Cache miss: file doesn't exist → fetches HTTP, writes cache
# ---------------------------------------------------------------------------

async def test_cache_miss(tmp_path, fake_bundle):
    cache_file = tmp_path / "mitre_cache.json"
    mock_client = _make_mock_client(fake_bundle)

    client = MITREClient(cache_path=cache_file, http_client=mock_client)
    techniques = await client._load()

    assert len(techniques) == 2
    assert cache_file.exists()
    mock_client.get.assert_called_once()


# ---------------------------------------------------------------------------
# 14. Cache stale: file older than 7 days → fetches HTTP
# ---------------------------------------------------------------------------

async def test_cache_stale(tmp_path, fake_bundle):
    cache_file = tmp_path / "mitre_cache.json"
    # Write file and backdate its mtime by 8 days
    cache_file.write_text(json.dumps(fake_bundle), encoding="utf-8")
    eight_days_ago = time.time() - (8 * 24 * 3600)
    import os
    os.utime(str(cache_file), (eight_days_ago, eight_days_ago))

    mock_client = _make_mock_client(fake_bundle)
    client = MITREClient(cache_path=cache_file, http_client=mock_client)

    techniques = await client._load()
    assert len(techniques) == 2
    # Should have fetched fresh data
    mock_client.get.assert_called_once()


# ---------------------------------------------------------------------------
# 15. clear_cache removes file and clears in-memory cache
# ---------------------------------------------------------------------------

async def test_clear_cache(tmp_path, fake_bundle):
    cache_file = tmp_path / "mitre_cache.json"
    mock_client = _make_mock_client(fake_bundle)
    client = MITREClient(cache_path=cache_file, http_client=mock_client)

    # Load once to populate in-memory cache and write file
    await client._load()
    assert cache_file.exists()
    assert client._techniques is not None

    # Clear
    client.clear_cache()
    assert not cache_file.exists()
    assert client._techniques is None
