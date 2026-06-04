"""Async tests for Storage (SQLAlchemy 2.0 Core + aiosqlite in-memory)."""
from __future__ import annotations

from datetime import date, datetime, timezone

import pytest

from redops.models.engagement import (
    Engagement,
    LogEntry,
    Objective,
    OpsecCheckResult,
    OpsecResult,
    TTP,
)
from redops.storage.db import Storage


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
async def storage():
    """In-memory SQLite storage, initialized and torn down per test."""
    s = Storage("sqlite+aiosqlite:///:memory:")
    await s.init()
    yield s
    await s.close()


def _engagement(**kwargs) -> Engagement:
    defaults = {
        "name": "Test Op",
        "client": "Client A",
        "start_date": date(2025, 1, 1),
        "end_date": date(2025, 6, 30),
    }
    defaults.update(kwargs)
    return Engagement(**defaults)


def _objective(engagement_id: str, **kwargs) -> Objective:
    defaults = {"engagement_id": engagement_id, "title": "Objective 1"}
    defaults.update(kwargs)
    return Objective(**defaults)


def _ttp(engagement_id: str, **kwargs) -> TTP:
    defaults = {"engagement_id": engagement_id, "technique_id": "T1078"}
    defaults.update(kwargs)
    return TTP(**defaults)


def _log_entry(engagement_id: str, **kwargs) -> LogEntry:
    defaults = {
        "engagement_id": engagement_id,
        "operator": "op1",
        "action": "Ran mimikatz",
        "target": "DC01",
    }
    defaults.update(kwargs)
    return LogEntry(**defaults)


def _opsec_result(domain: str = "example.com", **kwargs) -> OpsecResult:
    defaults = {"domain": domain}
    defaults.update(kwargs)
    return OpsecResult(**defaults)


# ── Engagement Tests ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_add_and_get_engagement(storage):
    eng = _engagement()
    await storage.add_engagement(eng)
    fetched = await storage.get_engagement(eng.id)
    assert fetched is not None
    assert fetched.id == eng.id
    assert fetched.name == "Test Op"


@pytest.mark.asyncio
async def test_get_nonexistent_engagement_returns_none(storage):
    result = await storage.get_engagement("nonexistent-id")
    assert result is None


@pytest.mark.asyncio
async def test_list_engagements_empty(storage):
    result = await storage.list_engagements()
    assert result == []


@pytest.mark.asyncio
async def test_list_engagements_multiple(storage):
    e1 = _engagement(name="Op Alpha")
    e2 = _engagement(name="Op Beta")
    await storage.add_engagement(e1)
    await storage.add_engagement(e2)
    result = await storage.list_engagements()
    assert len(result) == 2
    names = {e.name for e in result}
    assert names == {"Op Alpha", "Op Beta"}


@pytest.mark.asyncio
async def test_update_engagement(storage):
    eng = _engagement()
    await storage.add_engagement(eng)
    eng.status = "active"
    eng.name = "Updated Name"
    await storage.update_engagement(eng)
    fetched = await storage.get_engagement(eng.id)
    assert fetched.status == "active"
    assert fetched.name == "Updated Name"


@pytest.mark.asyncio
async def test_update_engagement_not_found(storage):
    eng = Engagement(name="X", client="C", start_date=date(2024, 1, 1), end_date=date(2024, 12, 31))
    with pytest.raises(KeyError):
        await storage.update_engagement(eng)


@pytest.mark.asyncio
async def test_delete_engagement(storage):
    eng = _engagement()
    await storage.add_engagement(eng)
    await storage.delete_engagement(eng.id)
    result = await storage.get_engagement(eng.id)
    assert result is None


@pytest.mark.asyncio
async def test_add_engagement_idempotent(storage):
    """INSERT OR IGNORE — adding same engagement twice doesn't raise, count stays 1."""
    eng = _engagement()
    await storage.add_engagement(eng)
    await storage.add_engagement(eng)  # should not raise
    result = await storage.list_engagements()
    assert len(result) == 1


@pytest.mark.asyncio
async def test_engagement_preserves_all_fields(storage):
    eng = _engagement(
        scope=["10.0.0.0/8", "192.168.0.0/16"],
        out_of_scope=["10.1.0.0/24"],
        operators=["alice", "bob"],
        rules_of_engagement="No destructive actions",
        status="active",
    )
    await storage.add_engagement(eng)
    fetched = await storage.get_engagement(eng.id)
    assert fetched.scope == ["10.0.0.0/8", "192.168.0.0/16"]
    assert fetched.out_of_scope == ["10.1.0.0/24"]
    assert fetched.operators == ["alice", "bob"]
    assert fetched.rules_of_engagement == "No destructive actions"
    assert fetched.status == "active"


# ── Objective Tests ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_add_and_get_objective(storage):
    eng = _engagement()
    await storage.add_engagement(eng)
    obj = _objective(eng.id, title="Exfiltrate PII")
    await storage.add_objective(obj)
    fetched = await storage.get_objective(obj.id)
    assert fetched is not None
    assert fetched.title == "Exfiltrate PII"
    assert fetched.engagement_id == eng.id


@pytest.mark.asyncio
async def test_get_nonexistent_objective_returns_none(storage):
    result = await storage.get_objective("missing-id")
    assert result is None


@pytest.mark.asyncio
async def test_list_objectives_filters_by_engagement(storage):
    e1 = _engagement(name="Op A")
    e2 = _engagement(name="Op B")
    await storage.add_engagement(e1)
    await storage.add_engagement(e2)
    o1 = _objective(e1.id, title="Goal A1")
    o2 = _objective(e1.id, title="Goal A2")
    o3 = _objective(e2.id, title="Goal B1")
    await storage.add_objective(o1)
    await storage.add_objective(o2)
    await storage.add_objective(o3)
    result = await storage.list_objectives(e1.id)
    assert len(result) == 2
    titles = {o.title for o in result}
    assert titles == {"Goal A1", "Goal A2"}


@pytest.mark.asyncio
async def test_update_objective(storage):
    eng = _engagement()
    await storage.add_engagement(eng)
    obj = _objective(eng.id)
    await storage.add_objective(obj)
    obj.status = "achieved"
    obj.description = "Done successfully"
    await storage.update_objective(obj)
    fetched = await storage.get_objective(obj.id)
    assert fetched.status == "achieved"
    assert fetched.description == "Done successfully"


@pytest.mark.asyncio
async def test_update_objective_not_found(storage):
    eng = _engagement()
    await storage.add_engagement(eng)
    obj = Objective(engagement_id=eng.id, title="Ghost")
    with pytest.raises(KeyError):
        await storage.update_objective(obj)


@pytest.mark.asyncio
async def test_add_objective_idempotent(storage):
    eng = _engagement()
    await storage.add_engagement(eng)
    obj = _objective(eng.id)
    await storage.add_objective(obj)
    await storage.add_objective(obj)  # should not raise
    result = await storage.list_objectives(eng.id)
    assert len(result) == 1


# ── TTP Tests ─────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_add_and_get_ttp(storage):
    eng = _engagement()
    await storage.add_engagement(eng)
    ttp = _ttp(eng.id, technique_id="T1059.001", technique_name="PowerShell")
    await storage.add_ttp(ttp)
    fetched = await storage.get_ttp(ttp.id)
    assert fetched is not None
    assert fetched.technique_id == "T1059.001"
    assert fetched.technique_name == "PowerShell"


@pytest.mark.asyncio
async def test_get_nonexistent_ttp_returns_none(storage):
    result = await storage.get_ttp("missing-ttp-id")
    assert result is None


@pytest.mark.asyncio
async def test_list_ttps_filters_by_engagement(storage):
    e1 = _engagement(name="Op 1")
    e2 = _engagement(name="Op 2")
    await storage.add_engagement(e1)
    await storage.add_engagement(e2)
    t1 = _ttp(e1.id, technique_id="T1078")
    t2 = _ttp(e1.id, technique_id="T1059")
    t3 = _ttp(e2.id, technique_id="T1021")
    await storage.add_ttp(t1)
    await storage.add_ttp(t2)
    await storage.add_ttp(t3)
    result = await storage.list_ttps(e1.id)
    assert len(result) == 2
    tids = {t.technique_id for t in result}
    assert tids == {"T1078", "T1059"}


@pytest.mark.asyncio
async def test_update_ttp(storage):
    eng = _engagement()
    await storage.add_engagement(eng)
    ttp = _ttp(eng.id)
    await storage.add_ttp(ttp)
    ttp.status = "executed"
    ttp.notes = "Ran via PowerShell"
    await storage.update_ttp(ttp)
    fetched = await storage.get_ttp(ttp.id)
    assert fetched.status == "executed"
    assert fetched.notes == "Ran via PowerShell"


@pytest.mark.asyncio
async def test_update_ttp_not_found(storage):
    eng = _engagement()
    await storage.add_engagement(eng)
    ttp = TTP(engagement_id=eng.id, technique_id="T9999")
    with pytest.raises(KeyError):
        await storage.update_ttp(ttp)


@pytest.mark.asyncio
async def test_add_ttp_idempotent(storage):
    eng = _engagement()
    await storage.add_engagement(eng)
    ttp = _ttp(eng.id)
    await storage.add_ttp(ttp)
    await storage.add_ttp(ttp)  # should not raise
    result = await storage.list_ttps(eng.id)
    assert len(result) == 1


# ── LogEntry Tests ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_add_and_list_log_entries(storage):
    eng = _engagement()
    await storage.add_engagement(eng)
    entry = _log_entry(eng.id, action="Spearphishing", result="success")
    await storage.add_log_entry(entry)
    result = await storage.list_log_entries(eng.id)
    assert len(result) == 1
    assert result[0].action == "Spearphishing"
    assert result[0].result == "success"


@pytest.mark.asyncio
async def test_list_log_entries_filters_by_engagement(storage):
    e1 = _engagement(name="Eng 1")
    e2 = _engagement(name="Eng 2")
    await storage.add_engagement(e1)
    await storage.add_engagement(e2)
    le1 = _log_entry(e1.id, action="Action A")
    le2 = _log_entry(e1.id, action="Action B")
    le3 = _log_entry(e2.id, action="Action C")
    await storage.add_log_entry(le1)
    await storage.add_log_entry(le2)
    await storage.add_log_entry(le3)
    result = await storage.list_log_entries(e1.id)
    assert len(result) == 2
    actions = {e.action for e in result}
    assert actions == {"Action A", "Action B"}


@pytest.mark.asyncio
async def test_list_log_entries_empty(storage):
    eng = _engagement()
    await storage.add_engagement(eng)
    result = await storage.list_log_entries(eng.id)
    assert result == []


@pytest.mark.asyncio
async def test_log_entry_preserves_evidence_refs(storage):
    eng = _engagement()
    await storage.add_engagement(eng)
    refs = ["screenshot.png", "dump.bin", "network.pcap"]
    entry = _log_entry(eng.id, evidence_refs=refs)
    await storage.add_log_entry(entry)
    result = await storage.list_log_entries(eng.id)
    assert result[0].evidence_refs == refs


@pytest.mark.asyncio
async def test_add_log_entry_idempotent(storage):
    eng = _engagement()
    await storage.add_engagement(eng)
    entry = _log_entry(eng.id)
    await storage.add_log_entry(entry)
    await storage.add_log_entry(entry)  # should not raise
    result = await storage.list_log_entries(eng.id)
    assert len(result) == 1


# ── OpsecResult Tests ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_add_and_list_opsec_results(storage):
    eng = _engagement()
    await storage.add_engagement(eng)
    checks = [
        OpsecCheckResult(name="DNS", status="pass"),
        OpsecCheckResult(name="WHOIS", status="warn", detail="Registrar exposed"),
    ]
    result = _opsec_result("target.com", checks=checks, score=60, grade="C")
    await storage.add_opsec_result(eng.id, result)
    fetched = await storage.list_opsec_results(eng.id)
    assert len(fetched) == 1
    assert fetched[0].domain == "target.com"
    assert fetched[0].score == 60
    assert fetched[0].grade == "C"
    assert len(fetched[0].checks) == 2


@pytest.mark.asyncio
async def test_list_opsec_results_filters_by_engagement(storage):
    e1 = _engagement(name="Eng A")
    e2 = _engagement(name="Eng B")
    await storage.add_engagement(e1)
    await storage.add_engagement(e2)
    r1 = _opsec_result("domain-a.com")
    r2 = _opsec_result("domain-b.com")
    r3 = _opsec_result("domain-c.com")
    await storage.add_opsec_result(e1.id, r1)
    await storage.add_opsec_result(e1.id, r2)
    await storage.add_opsec_result(e2.id, r3)
    result = await storage.list_opsec_results(e1.id)
    assert len(result) == 2
    domains = {r.domain for r in result}
    assert domains == {"domain-a.com", "domain-b.com"}


@pytest.mark.asyncio
async def test_list_opsec_results_empty(storage):
    eng = _engagement()
    await storage.add_engagement(eng)
    result = await storage.list_opsec_results(eng.id)
    assert result == []


@pytest.mark.asyncio
async def test_add_opsec_result_idempotent(storage):
    eng = _engagement()
    await storage.add_engagement(eng)
    r = _opsec_result()
    await storage.add_opsec_result(eng.id, r)
    await storage.add_opsec_result(eng.id, r)  # should not raise
    result = await storage.list_opsec_results(eng.id)
    assert len(result) == 1
