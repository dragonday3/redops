import json
import io
from datetime import date, datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import httpx
from httpx import AsyncClient, ASGITransport

from redops.api.app import app, get_storage
from redops.storage.db import Storage
from redops.models.engagement import (
    Engagement, Objective, TTP, LogEntry, OpsecResult, OpsecCheckResult
)


@pytest.fixture
async def storage():
    s = Storage("sqlite+aiosqlite:///:memory:")
    await s.init()
    yield s
    await s.close()


@pytest.fixture
async def client(storage):
    app.dependency_overrides[get_storage] = lambda: storage
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture
def sample_engagement():
    return Engagement(
        name="Op Test",
        client="TestCorp",
        start_date=date(2024, 1, 1),
        end_date=date(2024, 12, 31),
        scope=["10.0.0.0/8"],
        operators=["alice"],
    )


# ── 1. Health ─────────────────────────────────────────────────────────────────

async def test_health(client):
    resp = await client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "version" in data


# ── 2. GET /engagements empty list ────────────────────────────────────────────

async def test_list_engagements_empty(client):
    resp = await client.get("/engagements")
    assert resp.status_code == 200
    assert resp.json() == []


# ── 3. POST /engagements ──────────────────────────────────────────────────────

async def test_create_engagement(client):
    payload = {
        "name": "Op Alpha",
        "client": "ACME",
        "start_date": "2024-01-01",
        "end_date": "2024-06-30",
        "scope": ["192.168.0.0/24"],
        "operators": ["bob"],
    }
    resp = await client.post("/engagements", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["name"] == "Op Alpha"
    assert "id" in data


# ── 4. GET /engagements/{id} ──────────────────────────────────────────────────

async def test_get_engagement(client, storage, sample_engagement):
    await storage.add_engagement(sample_engagement)
    resp = await client.get(f"/engagements/{sample_engagement.id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["name"] == "Op Test"
    assert data["client"] == "TestCorp"


# ── 5. GET /engagements/{bad_id} → 404 ───────────────────────────────────────

async def test_get_engagement_not_found(client):
    resp = await client.get("/engagements/nonexistent-id")
    assert resp.status_code == 404


# ── 6. PATCH /engagements/{id} ────────────────────────────────────────────────

async def test_patch_engagement(client, storage, sample_engagement):
    await storage.add_engagement(sample_engagement)
    resp = await client.patch(
        f"/engagements/{sample_engagement.id}",
        json={"status": "active"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "active"


# ── 7. PATCH /engagements/{bad_id} → 404 ─────────────────────────────────────

async def test_patch_engagement_not_found(client):
    resp = await client.patch("/engagements/no-such-id", json={"status": "active"})
    assert resp.status_code == 404


# ── 8. DELETE /engagements/{id} ───────────────────────────────────────────────

async def test_delete_engagement(client, storage, sample_engagement):
    await storage.add_engagement(sample_engagement)
    resp = await client.delete(f"/engagements/{sample_engagement.id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["deleted"] == sample_engagement.id
    # Confirm it's gone
    resp2 = await client.get(f"/engagements/{sample_engagement.id}")
    assert resp2.status_code == 404


# ── 9. DELETE /engagements/{bad_id} → 404 ────────────────────────────────────

async def test_delete_engagement_not_found(client):
    resp = await client.delete("/engagements/no-such-id")
    assert resp.status_code == 404


# ── 10. POST /engagements/{id}/objectives ────────────────────────────────────

async def test_create_objective(client, storage, sample_engagement):
    await storage.add_engagement(sample_engagement)
    resp = await client.post(
        f"/engagements/{sample_engagement.id}/objectives",
        json={"title": "Gain initial access", "description": "Phishing"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["title"] == "Gain initial access"
    assert data["engagement_id"] == sample_engagement.id
    assert "id" in data


# ── 11. GET /engagements/{id}/objectives ─────────────────────────────────────

async def test_list_objectives(client, storage, sample_engagement):
    await storage.add_engagement(sample_engagement)
    obj = Objective(engagement_id=sample_engagement.id, title="Obj1")
    await storage.add_objective(obj)
    resp = await client.get(f"/engagements/{sample_engagement.id}/objectives")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["title"] == "Obj1"


# ── 12. PATCH /engagements/{id}/objectives/{oid} ─────────────────────────────

async def test_patch_objective(client, storage, sample_engagement):
    await storage.add_engagement(sample_engagement)
    obj = Objective(engagement_id=sample_engagement.id, title="Obj1")
    await storage.add_objective(obj)
    resp = await client.patch(
        f"/engagements/{sample_engagement.id}/objectives/{obj.id}",
        json={"status": "achieved"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "achieved"


# ── 13. PATCH /engagements/{id}/objectives/{bad_oid} → 404 ───────────────────

async def test_patch_objective_not_found(client, storage, sample_engagement):
    await storage.add_engagement(sample_engagement)
    resp = await client.patch(
        f"/engagements/{sample_engagement.id}/objectives/no-such-obj",
        json={"status": "achieved"},
    )
    assert resp.status_code == 404


# ── 14. POST /engagements/{id}/ttps ──────────────────────────────────────────

async def test_create_ttp(client, storage, sample_engagement):
    await storage.add_engagement(sample_engagement)
    resp = await client.post(
        f"/engagements/{sample_engagement.id}/ttps",
        json={"technique_id": "T1059", "technique_name": "Command Scripting", "tactic": "execution"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["technique_id"] == "T1059"
    assert data["engagement_id"] == sample_engagement.id


# ── 15. GET /engagements/{id}/ttps ───────────────────────────────────────────

async def test_list_ttps(client, storage, sample_engagement):
    await storage.add_engagement(sample_engagement)
    ttp = TTP(engagement_id=sample_engagement.id, technique_id="T1059", tactic="execution")
    await storage.add_ttp(ttp)
    resp = await client.get(f"/engagements/{sample_engagement.id}/ttps")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["technique_id"] == "T1059"


# ── 16. PATCH /engagements/{id}/ttps/{tid} ───────────────────────────────────

async def test_patch_ttp(client, storage, sample_engagement):
    await storage.add_engagement(sample_engagement)
    ttp = TTP(engagement_id=sample_engagement.id, technique_id="T1059", tactic="execution")
    await storage.add_ttp(ttp)
    resp = await client.patch(
        f"/engagements/{sample_engagement.id}/ttps/{ttp.id}",
        json={"status": "executed"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "executed"


# ── 17. POST /engagements/{id}/log ───────────────────────────────────────────

async def test_create_log_entry(client, storage, sample_engagement):
    await storage.add_engagement(sample_engagement)
    resp = await client.post(
        f"/engagements/{sample_engagement.id}/log",
        json={
            "operator": "alice",
            "action": "Ran mimikatz",
            "target": "DC01",
            "result": "success",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["operator"] == "alice"
    assert data["action"] == "Ran mimikatz"
    assert data["engagement_id"] == sample_engagement.id


# ── 18. GET /engagements/{id}/log sorted by timestamp ────────────────────────

async def test_list_log_sorted(client, storage, sample_engagement):
    await storage.add_engagement(sample_engagement)
    e1 = LogEntry(
        engagement_id=sample_engagement.id,
        operator="alice",
        action="First",
        target="T1",
        timestamp=datetime(2024, 1, 1, 10, 0, 0, tzinfo=timezone.utc),
    )
    e2 = LogEntry(
        engagement_id=sample_engagement.id,
        operator="bob",
        action="Second",
        target="T2",
        timestamp=datetime(2024, 1, 1, 9, 0, 0, tzinfo=timezone.utc),
    )
    await storage.add_log_entry(e1)
    await storage.add_log_entry(e2)
    resp = await client.get(f"/engagements/{sample_engagement.id}/log")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 2
    # Second entry (9:00) should come first when sorted
    assert data[0]["action"] == "Second"
    assert data[1]["action"] == "First"


# ── 19. POST /engagements/{id}/opsec (mock OpsecEngine.run) ──────────────────

async def test_post_opsec(client, storage, sample_engagement):
    await storage.add_engagement(sample_engagement)
    mock_result = OpsecResult(
        domain="example.com",
        score=85,
        grade="B",
        checks=[OpsecCheckResult(name="ssl_validity", status="pass")],
    )
    with patch("redops.api.app.OpsecEngine") as MockEngine:
        mock_engine_instance = MagicMock()
        mock_engine_instance.run = AsyncMock(return_value=mock_result)
        MockEngine.return_value = mock_engine_instance
        resp = await client.post(
            f"/engagements/{sample_engagement.id}/opsec",
            json={"domain": "example.com"},
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["domain"] == "example.com"
    assert data["grade"] == "B"
    assert data["score"] == 85


# ── 20. GET /engagements/{id}/opsec ──────────────────────────────────────────

async def test_list_opsec(client, storage, sample_engagement):
    await storage.add_engagement(sample_engagement)
    result = OpsecResult(
        domain="example.com",
        score=70,
        grade="C",
        checks=[OpsecCheckResult(name="ssl_validity", status="pass")],
    )
    await storage.add_opsec_result(sample_engagement.id, result)
    resp = await client.get(f"/engagements/{sample_engagement.id}/opsec")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["domain"] == "example.com"
    assert data[0]["grade"] == "C"


# ── 21. POST /engagements/{id}/report?format=json ────────────────────────────

async def test_report_json(client, storage, sample_engagement):
    await storage.add_engagement(sample_engagement)
    resp = await client.post(f"/engagements/{sample_engagement.id}/report?format=json")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/json")
    data = resp.json()
    assert "engagement" in data
    assert "objectives" in data
    assert "ttps" in data


# ── 22. POST /engagements/{id}/report?format=html ────────────────────────────

async def test_report_html(client, storage, sample_engagement):
    await storage.add_engagement(sample_engagement)
    resp = await client.post(f"/engagements/{sample_engagement.id}/report?format=html")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "report.html" in resp.headers.get("content-disposition", "")


# ── 23. POST /engagements/{id}/report?format=docx ────────────────────────────

async def test_report_docx(client, storage, sample_engagement):
    await storage.add_engagement(sample_engagement)
    resp = await client.post(f"/engagements/{sample_engagement.id}/report?format=docx")
    assert resp.status_code == 200
    ct = resp.headers["content-type"]
    assert "wordprocessingml" in ct or "openxmlformats" in ct
    assert "report.docx" in resp.headers.get("content-disposition", "")


# ── 24. POST /engagements/{id}/report?format=bad → 400 ───────────────────────

async def test_report_bad_format(client, storage, sample_engagement):
    await storage.add_engagement(sample_engagement)
    resp = await client.post(f"/engagements/{sample_engagement.id}/report?format=bad")
    assert resp.status_code == 400


# ── 25. POST /engagements/{id}/report?format=pdf (mock WeasyPrint) ────────────

async def test_report_pdf(client, storage, sample_engagement):
    await storage.add_engagement(sample_engagement)
    with patch("redops.reporters.pdf.PDFReporter.generate", return_value=b"%PDF-fake"):
        resp = await client.post(f"/engagements/{sample_engagement.id}/report?format=pdf")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert "report.pdf" in resp.headers.get("content-disposition", "")
    assert resp.content == b"%PDF-fake"
