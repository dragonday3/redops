from __future__ import annotations
from datetime import date, datetime, timezone
from typing import Literal
import uuid
from pydantic import BaseModel, Field


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _uuid() -> str:
    return str(uuid.uuid4())


# ── Engagement ────────────────────────────────────────────────────────────────

EngagementStatus = Literal["planning", "active", "completed", "cancelled"]

class Engagement(BaseModel):
    id: str = Field(default_factory=_uuid)
    name: str
    client: str
    scope: list[str] = Field(default_factory=list)
    out_of_scope: list[str] = Field(default_factory=list)
    rules_of_engagement: str = ""
    start_date: date
    end_date: date
    operators: list[str] = Field(default_factory=list)
    status: EngagementStatus = "planning"
    created_at: datetime = Field(default_factory=_now)


# ── Objective ─────────────────────────────────────────────────────────────────

ObjectiveType = Literal["primary", "secondary"]
ObjectiveStatus = Literal["pending", "achieved", "failed", "partial"]

class Objective(BaseModel):
    id: str = Field(default_factory=_uuid)
    engagement_id: str
    title: str
    description: str = ""
    type: ObjectiveType = "primary"
    status: ObjectiveStatus = "pending"
    completed_at: datetime | None = None


# ── TTP ───────────────────────────────────────────────────────────────────────

TTPStatus = Literal["planned", "executed", "detected", "blocked"]

class TTP(BaseModel):
    id: str = Field(default_factory=_uuid)
    engagement_id: str
    technique_id: str
    technique_name: str = ""
    tactic: str = ""
    phase: str = ""
    status: TTPStatus = "planned"
    notes: str = ""


# ── Operator Log ──────────────────────────────────────────────────────────────

LogResult = Literal["success", "failure", "partial", "unknown"]

class LogEntry(BaseModel):
    id: str = Field(default_factory=_uuid)
    engagement_id: str
    timestamp: datetime = Field(default_factory=_now)
    operator: str
    action: str
    technique_id: str | None = None
    target: str
    result: LogResult = "unknown"
    notes: str = ""
    evidence_refs: list[str] = Field(default_factory=list)


# ── OPSEC ─────────────────────────────────────────────────────────────────────

CheckStatus = Literal["pass", "warn", "fail", "skip"]
OpsecGrade = Literal["A", "B", "C", "D", "F"]

class OpsecCheckResult(BaseModel):
    name: str
    status: CheckStatus
    detail: str = ""
    remediation: str = ""


class OpsecResult(BaseModel):
    id: str = Field(default_factory=_uuid)
    domain: str
    timestamp: datetime = Field(default_factory=_now)
    checks: list[OpsecCheckResult] = Field(default_factory=list)
    score: int = 0
    grade: OpsecGrade = "F"


# ── MITRE Technique ───────────────────────────────────────────────────────────

class Technique(BaseModel):
    id: str
    name: str
    tactic: str
    description: str = ""
    url: str = ""


# ── Report ────────────────────────────────────────────────────────────────────

ReportFormat = Literal["json", "html", "pdf", "docx"]
