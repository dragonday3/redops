"""Tests for Pydantic v2 models in redops.models.engagement."""
from __future__ import annotations

import uuid
from datetime import date, datetime, timezone

import pytest
from pydantic import ValidationError

from redops.models.engagement import (
    CheckStatus,
    Engagement,
    EngagementStatus,
    LogEntry,
    Objective,
    OpsecCheckResult,
    OpsecGrade,
    OpsecResult,
    Technique,
    TTP,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_engagement(**kwargs) -> Engagement:
    defaults = {
        "name": "Test Engagement",
        "client": "Acme Corp",
        "start_date": date(2025, 1, 1),
        "end_date": date(2025, 3, 31),
    }
    defaults.update(kwargs)
    return Engagement(**defaults)


def make_objective(**kwargs) -> Objective:
    defaults = {
        "engagement_id": str(uuid.uuid4()),
        "title": "Gain Domain Admin",
    }
    defaults.update(kwargs)
    return Objective(**defaults)


def make_ttp(**kwargs) -> TTP:
    defaults = {
        "engagement_id": str(uuid.uuid4()),
        "technique_id": "T1078",
    }
    defaults.update(kwargs)
    return TTP(**defaults)


def make_log_entry(**kwargs) -> LogEntry:
    defaults = {
        "engagement_id": str(uuid.uuid4()),
        "operator": "op1",
        "action": "Phishing email sent",
        "target": "victim@target.com",
    }
    defaults.update(kwargs)
    return LogEntry(**defaults)


# ── Engagement Tests ──────────────────────────────────────────────────────────

def test_engagement_id_auto_generated():
    eng = make_engagement()
    assert eng.id
    assert len(eng.id) == 36  # UUID4 string length


def test_engagement_id_unique():
    e1 = make_engagement()
    e2 = make_engagement()
    assert e1.id != e2.id


def test_engagement_default_status_is_planning():
    eng = make_engagement()
    assert eng.status == "planning"


def test_engagement_created_at_is_datetime():
    eng = make_engagement()
    assert isinstance(eng.created_at, datetime)


def test_engagement_created_at_is_utc():
    eng = make_engagement()
    assert eng.created_at.tzinfo is not None
    assert eng.created_at.tzinfo == timezone.utc


def test_engagement_scope_defaults_to_empty_list():
    eng = make_engagement()
    assert eng.scope == []


def test_engagement_out_of_scope_defaults_to_empty_list():
    eng = make_engagement()
    assert eng.out_of_scope == []


def test_engagement_operators_defaults_to_empty_list():
    eng = make_engagement()
    assert eng.operators == []


def test_engagement_rules_of_engagement_defaults_empty_string():
    eng = make_engagement()
    assert eng.rules_of_engagement == ""


def test_engagement_all_status_literals():
    for status in ("planning", "active", "completed", "cancelled"):
        eng = make_engagement(status=status)
        assert eng.status == status


def test_engagement_invalid_status_raises():
    with pytest.raises(ValidationError):
        make_engagement(status="unknown")


def test_engagement_date_fields():
    eng = make_engagement(start_date=date(2025, 6, 1), end_date=date(2025, 12, 31))
    assert eng.start_date == date(2025, 6, 1)
    assert eng.end_date == date(2025, 12, 31)


def test_engagement_serialization_round_trip():
    eng = make_engagement(
        name="Round Trip",
        client="Client X",
        scope=["10.0.0.0/8"],
        operators=["alice", "bob"],
        status="active",
    )
    json_str = eng.model_dump_json()
    restored = Engagement.model_validate_json(json_str)
    assert restored == eng


# ── Objective Tests ───────────────────────────────────────────────────────────

def test_objective_id_auto_generated():
    obj = make_objective()
    assert obj.id
    assert len(obj.id) == 36


def test_objective_default_type_is_primary():
    obj = make_objective()
    assert obj.type == "primary"


def test_objective_default_status_is_pending():
    obj = make_objective()
    assert obj.status == "pending"


def test_objective_completed_at_is_nullable():
    obj = make_objective()
    assert obj.completed_at is None


def test_objective_completed_at_accepts_datetime():
    now = datetime.now(timezone.utc)
    obj = make_objective(completed_at=now)
    assert obj.completed_at == now


def test_objective_type_literals():
    for t in ("primary", "secondary"):
        obj = make_objective(type=t)
        assert obj.type == t


def test_objective_status_literals():
    for s in ("pending", "achieved", "failed", "partial"):
        obj = make_objective(status=s)
        assert obj.status == s


def test_objective_invalid_status_raises():
    with pytest.raises(ValidationError):
        make_objective(status="done")


def test_objective_serialization_round_trip():
    obj = make_objective(title="Pivot to DC", description="Reach domain controller", type="primary")
    json_str = obj.model_dump_json()
    restored = Objective.model_validate_json(json_str)
    assert restored == obj


# ── TTP Tests ─────────────────────────────────────────────────────────────────

def test_ttp_id_auto_generated():
    ttp = make_ttp()
    assert ttp.id
    assert len(ttp.id) == 36


def test_ttp_default_status_is_planned():
    ttp = make_ttp()
    assert ttp.status == "planned"


def test_ttp_string_defaults():
    ttp = make_ttp()
    assert ttp.technique_name == ""
    assert ttp.tactic == ""
    assert ttp.phase == ""
    assert ttp.notes == ""


def test_ttp_status_literals():
    for s in ("planned", "executed", "detected", "blocked"):
        ttp = make_ttp(status=s)
        assert ttp.status == s


def test_ttp_invalid_status_raises():
    with pytest.raises(ValidationError):
        make_ttp(status="running")


def test_ttp_serialization_round_trip():
    ttp = make_ttp(
        technique_id="T1059.001",
        technique_name="PowerShell",
        tactic="Execution",
        phase="Initial Access",
        status="executed",
    )
    json_str = ttp.model_dump_json()
    restored = TTP.model_validate_json(json_str)
    assert restored == ttp


# ── LogEntry Tests ────────────────────────────────────────────────────────────

def test_log_entry_id_auto_generated():
    entry = make_log_entry()
    assert entry.id
    assert len(entry.id) == 36


def test_log_entry_timestamp_is_utc():
    entry = make_log_entry()
    assert entry.timestamp.tzinfo is not None
    assert entry.timestamp.tzinfo == timezone.utc


def test_log_entry_technique_id_is_nullable():
    entry = make_log_entry()
    assert entry.technique_id is None


def test_log_entry_technique_id_accepts_string():
    entry = make_log_entry(technique_id="T1566.001")
    assert entry.technique_id == "T1566.001"


def test_log_entry_default_result_is_unknown():
    entry = make_log_entry()
    assert entry.result == "unknown"


def test_log_entry_evidence_refs_defaults_empty():
    entry = make_log_entry()
    assert entry.evidence_refs == []


def test_log_entry_evidence_refs_accepts_list():
    refs = ["screenshot1.png", "pcap1.pcapng"]
    entry = make_log_entry(evidence_refs=refs)
    assert entry.evidence_refs == refs


def test_log_entry_result_literals():
    for r in ("success", "failure", "partial", "unknown"):
        entry = make_log_entry(result=r)
        assert entry.result == r


def test_log_entry_invalid_result_raises():
    with pytest.raises(ValidationError):
        make_log_entry(result="error")


def test_log_entry_serialization_round_trip():
    entry = make_log_entry(
        technique_id="T1078",
        result="success",
        notes="Credentials obtained",
        evidence_refs=["creds.txt"],
    )
    json_str = entry.model_dump_json()
    restored = LogEntry.model_validate_json(json_str)
    assert restored == entry


# ── OpsecCheckResult Tests ────────────────────────────────────────────────────

def test_opsec_check_result_status_literals():
    for s in ("pass", "warn", "fail", "skip"):
        check = OpsecCheckResult(name="DNS Check", status=s)
        assert check.status == s


def test_opsec_check_result_defaults():
    check = OpsecCheckResult(name="WHOIS Check", status="pass")
    assert check.detail == ""
    assert check.remediation == ""


def test_opsec_check_result_invalid_status_raises():
    with pytest.raises(ValidationError):
        OpsecCheckResult(name="X", status="ok")


# ── OpsecResult Tests ─────────────────────────────────────────────────────────

def test_opsec_result_id_auto_generated():
    result = OpsecResult(domain="example.com")
    assert result.id
    assert len(result.id) == 36


def test_opsec_result_score_default_zero():
    result = OpsecResult(domain="example.com")
    assert result.score == 0


def test_opsec_result_grade_default_f():
    result = OpsecResult(domain="example.com")
    assert result.grade == "F"


def test_opsec_result_checks_default_empty():
    result = OpsecResult(domain="example.com")
    assert result.checks == []


def test_opsec_result_grade_literals():
    for g in ("A", "B", "C", "D", "F"):
        result = OpsecResult(domain="example.com", grade=g)
        assert result.grade == g


def test_opsec_result_with_checks():
    checks = [
        OpsecCheckResult(name="DNS", status="pass", detail="No leaks"),
        OpsecCheckResult(name="WHOIS", status="warn", detail="Registrar visible", remediation="Use privacy guard"),
    ]
    result = OpsecResult(domain="example.com", checks=checks, score=75, grade="B")
    assert len(result.checks) == 2
    assert result.score == 75
    assert result.grade == "B"


def test_opsec_result_serialization_round_trip():
    checks = [OpsecCheckResult(name="SPF", status="fail", detail="No SPF record")]
    result = OpsecResult(domain="target.com", checks=checks, score=20, grade="D")
    json_str = result.model_dump_json()
    restored = OpsecResult.model_validate_json(json_str)
    assert restored == result


# ── Technique Tests ───────────────────────────────────────────────────────────

def test_technique_all_fields():
    t = Technique(
        id="T1059.001",
        name="PowerShell",
        tactic="Execution",
        description="Adversaries may abuse PowerShell commands.",
        url="https://attack.mitre.org/techniques/T1059/001/",
    )
    assert t.id == "T1059.001"
    assert t.name == "PowerShell"
    assert t.tactic == "Execution"
    assert t.description == "Adversaries may abuse PowerShell commands."
    assert t.url == "https://attack.mitre.org/techniques/T1059/001/"


def test_technique_optional_fields_default():
    t = Technique(id="T1078", name="Valid Accounts", tactic="Defense Evasion")
    assert t.description == ""
    assert t.url == ""


def test_technique_serialization_round_trip():
    t = Technique(
        id="T1021.002",
        name="SMB/Windows Admin Shares",
        tactic="Lateral Movement",
        description="Adversaries may use SMB.",
        url="https://attack.mitre.org/techniques/T1021/002/",
    )
    json_str = t.model_dump_json()
    restored = Technique.model_validate_json(json_str)
    assert restored == t
