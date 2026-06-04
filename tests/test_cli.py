import json
import sys
import types
from datetime import date
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from typer.testing import CliRunner

from redops.cli import app
from redops.models.engagement import (
    Engagement, Objective, TTP, LogEntry, OpsecResult, OpsecCheckResult
)
from redops.storage.db import Storage


runner = CliRunner()


@pytest.fixture
def in_memory_storage(tmp_path):
    """Return a DB URL pointing to a temp sqlite file."""
    return f"sqlite+aiosqlite:///{tmp_path}/test.db"


@pytest.fixture
def sample_engagement():
    return Engagement(
        name="Op Test",
        client="ACME",
        start_date=date(2024, 1, 1),
        end_date=date(2024, 12, 31),
        operators=["alice"],
    )


# ── helper to seed DB ─────────────────────────────────────────────────────────

async def _seed_engagement(db_url: str, engagement: Engagement) -> None:
    import asyncio
    s = Storage(db_url)
    await s.init()
    await s.add_engagement(engagement)
    await s.close()


async def _seed_objective(db_url: str, obj: Objective) -> None:
    s = Storage(db_url)
    await s.init()
    await s.add_objective(obj)
    await s.close()


async def _seed_ttp(db_url: str, ttp: TTP) -> None:
    s = Storage(db_url)
    await s.init()
    await s.add_ttp(ttp)
    await s.close()


import asyncio as _asyncio


def _run(coro):
    return _asyncio.run(coro)


# ── 1. engagement create → creates and returns JSON ──────────────────────────

def test_engagement_create(in_memory_storage):
    with patch("redops.cli.DB_URL", in_memory_storage):
        result = runner.invoke(app, [
            "engagement", "create",
            "--name", "Op Test",
            "--client", "ACME",
            "--start", "2024-01-01",
            "--end", "2024-12-31",
        ])
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert data["name"] == "Op Test"
    assert data["client"] == "ACME"
    assert "id" in data


# ── 2. engagement list → shows table (exit 0) ────────────────────────────────

def test_engagement_list(in_memory_storage, sample_engagement):
    _run(_seed_engagement(in_memory_storage, sample_engagement))
    with patch("redops.cli.DB_URL", in_memory_storage):
        result = runner.invoke(app, ["engagement", "list"])
    assert result.exit_code == 0, result.output
    assert "Op Test" in result.output


# ── 3. engagement show <id> → shows JSON ─────────────────────────────────────

def test_engagement_show(in_memory_storage, sample_engagement):
    _run(_seed_engagement(in_memory_storage, sample_engagement))
    with patch("redops.cli.DB_URL", in_memory_storage):
        result = runner.invoke(app, ["engagement", "show", sample_engagement.id])
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert data["name"] == "Op Test"
    assert data["id"] == sample_engagement.id


# ── 4. engagement show <bad_id> → exit 1 ─────────────────────────────────────

def test_engagement_show_not_found(in_memory_storage):
    with patch("redops.cli.DB_URL", in_memory_storage):
        result = runner.invoke(app, ["engagement", "show", "nonexistent-id"])
    assert result.exit_code == 1


# ── 5. objective add <id> --title X → creates objective ──────────────────────

def test_objective_add(in_memory_storage, sample_engagement):
    _run(_seed_engagement(in_memory_storage, sample_engagement))
    with patch("redops.cli.DB_URL", in_memory_storage):
        result = runner.invoke(app, [
            "objective", "add", sample_engagement.id,
            "--title", "Gain initial access",
        ])
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert data["title"] == "Gain initial access"
    assert "id" in data


# ── 6. objective complete <eng_id> <obj_id> → updates status ─────────────────

def test_objective_complete(in_memory_storage, sample_engagement):
    _run(_seed_engagement(in_memory_storage, sample_engagement))
    obj = Objective(engagement_id=sample_engagement.id, title="Obj1")
    _run(_seed_objective(in_memory_storage, obj))
    with patch("redops.cli.DB_URL", in_memory_storage):
        result = runner.invoke(app, [
            "objective", "complete",
            sample_engagement.id, obj.id,
        ])
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert data["status"] == "achieved"
    assert data["id"] == obj.id


# ── 7. objective complete <eng_id> <bad_id> → exit 1 ─────────────────────────

def test_objective_complete_not_found(in_memory_storage, sample_engagement):
    _run(_seed_engagement(in_memory_storage, sample_engagement))
    with patch("redops.cli.DB_URL", in_memory_storage):
        result = runner.invoke(app, [
            "objective", "complete",
            sample_engagement.id, "nonexistent-obj-id",
        ])
    assert result.exit_code == 1


# ── 8. ttp add <id> --technique T1566.001 → creates TTP ──────────────────────

def test_ttp_add(in_memory_storage, sample_engagement):
    _run(_seed_engagement(in_memory_storage, sample_engagement))
    with patch("redops.cli.DB_URL", in_memory_storage):
        result = runner.invoke(app, [
            "ttp", "add", sample_engagement.id,
            "--technique", "T1566.001",
            "--name", "Spearphishing",
            "--tactic", "initial-access",
        ])
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert data["technique_id"] == "T1566.001"
    assert "id" in data


# ── 9. ttp list <id> → shows table ───────────────────────────────────────────

def test_ttp_list(in_memory_storage, sample_engagement):
    _run(_seed_engagement(in_memory_storage, sample_engagement))
    ttp = TTP(engagement_id=sample_engagement.id, technique_id="T1059", tactic="execution")
    _run(_seed_ttp(in_memory_storage, ttp))
    with patch("redops.cli.DB_URL", in_memory_storage):
        result = runner.invoke(app, ["ttp", "list", sample_engagement.id])
    assert result.exit_code == 0, result.output
    assert "T1059" in result.output


# ── 10. log add → creates log entry ──────────────────────────────────────────

def test_log_add(in_memory_storage, sample_engagement):
    _run(_seed_engagement(in_memory_storage, sample_engagement))
    with patch("redops.cli.DB_URL", in_memory_storage):
        result = runner.invoke(app, [
            "log", "add", sample_engagement.id,
            "--operator", "alice",
            "--action", "Ran mimikatz",
            "--target", "DC01",
            "--result", "success",
        ])
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert data["result"] == "success"
    assert "id" in data


# ── 11. log show <id> → shows table ──────────────────────────────────────────

def test_log_show(in_memory_storage, sample_engagement):
    _run(_seed_engagement(in_memory_storage, sample_engagement))
    # Add a log entry first
    with patch("redops.cli.DB_URL", in_memory_storage):
        runner.invoke(app, [
            "log", "add", sample_engagement.id,
            "--operator", "bob",
            "--action", "Recon scan",
            "--target", "10.0.0.1",
            "--result", "partial",
        ])
        result = runner.invoke(app, ["log", "show", sample_engagement.id])
    assert result.exit_code == 0, result.output
    assert "bob" in result.output
    assert "Recon scan" in result.output


# ── 12. opsec run example.com (mock OpsecEngine) → exit 0 for grade A ────────

def test_opsec_run_pass(in_memory_storage):
    mock_result = OpsecResult(
        domain="example.com",
        score=95,
        grade="A",
        checks=[OpsecCheckResult(name="ssl_validity", status="pass", detail="OK", remediation="")],
    )
    with patch("redops.cli.DB_URL", in_memory_storage):
        with patch("redops.opsec.engine.OpsecEngine") as MockEngine:
            mock_instance = MagicMock()
            mock_instance.run = AsyncMock(return_value=mock_result)
            MockEngine.return_value = mock_instance
            result = runner.invoke(app, ["opsec", "run", "example.com"])
    assert result.exit_code == 0, result.output + result.stderr


# ── 13. opsec run bad-domain.com (mock OpsecEngine, grade F) → exit 1 ────────

def test_opsec_run_fail_grade(in_memory_storage):
    mock_result = OpsecResult(
        domain="bad-domain.com",
        score=20,
        grade="F",
        checks=[OpsecCheckResult(name="ssl_validity", status="fail", detail="No SSL", remediation="Add SSL")],
    )
    with patch("redops.cli.DB_URL", in_memory_storage):
        with patch("redops.opsec.engine.OpsecEngine") as MockEngine:
            mock_instance = MagicMock()
            mock_instance.run = AsyncMock(return_value=mock_result)
            MockEngine.return_value = mock_instance
            result = runner.invoke(app, ["opsec", "run", "bad-domain.com"])
    assert result.exit_code == 1


# ── 14. report generate --format json → writes file ──────────────────────────

def test_report_generate_json(in_memory_storage, sample_engagement, tmp_path):
    _run(_seed_engagement(in_memory_storage, sample_engagement))
    out_file = str(tmp_path / "report.json")
    with patch("redops.cli.DB_URL", in_memory_storage):
        result = runner.invoke(app, [
            "report", "generate", sample_engagement.id,
            "--format", "json",
            "--out-file", out_file,
        ])
    assert result.exit_code == 0, result.output + result.stderr
    assert Path(out_file).exists()
    data = json.loads(Path(out_file).read_text(encoding="utf-8"))
    assert "engagement" in data


# ── 15. report generate --format html → writes file ──────────────────────────

def test_report_generate_html(in_memory_storage, sample_engagement, tmp_path):
    _run(_seed_engagement(in_memory_storage, sample_engagement))
    out_file = str(tmp_path / "report.html")
    with patch("redops.cli.DB_URL", in_memory_storage):
        result = runner.invoke(app, [
            "report", "generate", sample_engagement.id,
            "--format", "html",
            "--out-file", out_file,
        ])
    assert result.exit_code == 0, result.output + result.stderr
    assert Path(out_file).exists()
    content = Path(out_file).read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in content


# ── 16. report generate --format bad → exit 1 ────────────────────────────────

def test_report_generate_bad_format(in_memory_storage, sample_engagement, tmp_path):
    _run(_seed_engagement(in_memory_storage, sample_engagement))
    out_file = str(tmp_path / "report.xyz")
    with patch("redops.cli.DB_URL", in_memory_storage):
        result = runner.invoke(app, [
            "report", "generate", sample_engagement.id,
            "--format", "bad",
            "--out-file", out_file,
        ])
    assert result.exit_code == 1


# ── 17. report generate <bad_id> → exit 1 ────────────────────────────────────

def test_report_generate_missing_engagement(in_memory_storage, tmp_path):
    out_file = str(tmp_path / "report.json")
    with patch("redops.cli.DB_URL", in_memory_storage):
        result = runner.invoke(app, [
            "report", "generate", "nonexistent-id",
            "--format", "json",
            "--out-file", out_file,
        ])
    assert result.exit_code == 1


# ── 18. engagement create without required options → exit 2 ──────────────────

def test_engagement_create_missing_options(in_memory_storage):
    with patch("redops.cli.DB_URL", in_memory_storage):
        result = runner.invoke(app, ["engagement", "create"])
    assert result.exit_code == 2


# ── 19. --help → exit 0 ──────────────────────────────────────────────────────

def test_help(in_memory_storage):
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "redops" in result.output.lower()


# ── 20. serve --help → exit 0 (don't actually run uvicorn) ───────────────────

def test_serve_help():
    result = runner.invoke(app, ["serve", "--help"])
    assert result.exit_code == 0
    assert "host" in result.output.lower() or "port" in result.output.lower()


# ── 21. engagement create with operators ─────────────────────────────────────

def test_engagement_create_with_operators(in_memory_storage):
    with patch("redops.cli.DB_URL", in_memory_storage):
        result = runner.invoke(app, [
            "engagement", "create",
            "--name", "Op Multi",
            "--client", "Corp",
            "--start", "2024-03-01",
            "--end", "2024-09-30",
            "--operator", "alice",
            "--operator", "bob",
        ])
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert "id" in data
    assert data["name"] == "Op Multi"


# ── 22. objective add with type secondary ────────────────────────────────────

def test_objective_add_secondary(in_memory_storage, sample_engagement):
    _run(_seed_engagement(in_memory_storage, sample_engagement))
    with patch("redops.cli.DB_URL", in_memory_storage):
        result = runner.invoke(app, [
            "objective", "add", sample_engagement.id,
            "--title", "Exfiltrate data",
            "--type", "secondary",
            "--description", "Move data out",
        ])
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert data["title"] == "Exfiltrate data"


# ── 23. ttp add with all fields ──────────────────────────────────────────────

def test_ttp_add_full(in_memory_storage, sample_engagement):
    _run(_seed_engagement(in_memory_storage, sample_engagement))
    with patch("redops.cli.DB_URL", in_memory_storage):
        result = runner.invoke(app, [
            "ttp", "add", sample_engagement.id,
            "--technique", "T1078",
            "--name", "Valid Accounts",
            "--tactic", "defense-evasion",
            "--phase", "Week 2",
        ])
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert data["technique_id"] == "T1078"


# ── 24. log add with technique ────────────────────────────────────────────────

def test_log_add_with_technique(in_memory_storage, sample_engagement):
    _run(_seed_engagement(in_memory_storage, sample_engagement))
    with patch("redops.cli.DB_URL", in_memory_storage):
        result = runner.invoke(app, [
            "log", "add", sample_engagement.id,
            "--operator", "alice",
            "--action", "Phishing email",
            "--target", "user@corp.com",
            "--result", "success",
            "--technique", "T1566.001",
            "--notes", "User clicked link",
        ])
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert data["result"] == "success"


# ── 25. report generate --format docx → writes file ──────────────────────────

def test_report_generate_docx(in_memory_storage, sample_engagement, tmp_path):
    _run(_seed_engagement(in_memory_storage, sample_engagement))
    out_file = str(tmp_path / "report.docx")
    with patch("redops.cli.DB_URL", in_memory_storage):
        result = runner.invoke(app, [
            "report", "generate", sample_engagement.id,
            "--format", "docx",
            "--out-file", out_file,
        ])
    assert result.exit_code == 0, result.output + result.stderr
    assert Path(out_file).exists()
    # DOCX files start with PK (zip magic bytes)
    content = Path(out_file).read_bytes()
    assert content[:2] == b"PK"


# ── 26. opsec run grade D → exit 1 ───────────────────────────────────────────

def test_opsec_run_grade_d(in_memory_storage):
    mock_result = OpsecResult(
        domain="risky.com",
        score=45,
        grade="D",
        checks=[OpsecCheckResult(name="domain_age", status="fail", detail="Too new", remediation="Wait")],
    )
    with patch("redops.cli.DB_URL", in_memory_storage):
        with patch("redops.opsec.engine.OpsecEngine") as MockEngine:
            mock_instance = MagicMock()
            mock_instance.run = AsyncMock(return_value=mock_result)
            MockEngine.return_value = mock_instance
            result = runner.invoke(app, ["opsec", "run", "risky.com"])
    assert result.exit_code == 1


# ── 27. engagement list empty → exit 0 ───────────────────────────────────────

def test_engagement_list_empty(in_memory_storage):
    with patch("redops.cli.DB_URL", in_memory_storage):
        result = runner.invoke(app, ["engagement", "list"])
    assert result.exit_code == 0


# ── 28. ttp list empty → exit 0 with table header ────────────────────────────

def test_ttp_list_empty(in_memory_storage, sample_engagement):
    _run(_seed_engagement(in_memory_storage, sample_engagement))
    with patch("redops.cli.DB_URL", in_memory_storage):
        result = runner.invoke(app, ["ttp", "list", sample_engagement.id])
    assert result.exit_code == 0


# ── 29. report generate pdf (mock weasyprint) ────────────────────────────────

def test_report_generate_pdf(in_memory_storage, sample_engagement, tmp_path):
    _run(_seed_engagement(in_memory_storage, sample_engagement))
    out_file = str(tmp_path / "report.pdf")

    mock_html_cls = MagicMock()
    mock_instance = MagicMock()
    mock_instance.write_pdf.return_value = b"%PDF-fake"
    mock_html_cls.return_value = mock_instance

    fake_weasyprint = types.ModuleType("weasyprint")
    fake_weasyprint.HTML = mock_html_cls

    with patch("redops.cli.DB_URL", in_memory_storage):
        with patch.dict(sys.modules, {"weasyprint": fake_weasyprint}):
            result = runner.invoke(app, [
                "report", "generate", sample_engagement.id,
                "--format", "pdf",
                "--out-file", out_file,
            ])
    assert result.exit_code == 0, result.output + result.stderr
    assert Path(out_file).exists()


# ── 30. engagement subcommand --help → exit 0 ────────────────────────────────

def test_engagement_help():
    result = runner.invoke(app, ["engagement", "--help"])
    assert result.exit_code == 0
