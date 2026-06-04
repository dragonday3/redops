import asyncio
import json
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from redops.storage.db import Storage
from redops.models.engagement import Engagement, Objective, TTP, LogEntry

app = typer.Typer(help="redops — Red Team Campaign Manager + OPSEC Validator")
err = Console(stderr=True)

# Database URL from env or default
import os
DB_URL = os.environ.get("DATABASE_URL", "sqlite+aiosqlite:///./redops.db")


def _run(coro):
    """Run an async coroutine from sync context."""
    return asyncio.run(coro)


async def _get_storage() -> Storage:
    s = Storage(DB_URL)
    await s.init()
    return s


# ── engagement subcommand group ───────────────────────────────────────────────
engagement_app = typer.Typer(help="Manage engagements")
app.add_typer(engagement_app, name="engagement")


@engagement_app.command("create")
def engagement_create(
    name: str = typer.Option(..., help="Engagement name"),
    client: str = typer.Option(..., help="Client name"),
    start: str = typer.Option(..., help="Start date YYYY-MM-DD"),
    end: str = typer.Option(..., help="End date YYYY-MM-DD"),
    operator: list[str] = typer.Option([], help="Operator name (repeatable)"),
):
    """Create a new engagement."""
    async def _go():
        storage = await _get_storage()
        try:
            eng = Engagement(
                name=name, client=client,
                start_date=date.fromisoformat(start),
                end_date=date.fromisoformat(end),
                operators=operator,
            )
            await storage.add_engagement(eng)
            typer.echo(json.dumps({"id": eng.id, "name": eng.name, "client": eng.client}))
        finally:
            await storage.close()
    _run(_go())


@engagement_app.command("list")
def engagement_list():
    """List all engagements."""
    async def _go():
        storage = await _get_storage()
        try:
            engagements = await storage.list_engagements()
            table = Table(title="Engagements")
            table.add_column("ID", style="dim")
            table.add_column("Name")
            table.add_column("Client")
            table.add_column("Status")
            table.add_column("Period")
            for e in engagements:
                table.add_row(e.id[:8], e.name, e.client, e.status,
                              f"{e.start_date} — {e.end_date}")
            from rich.console import Console as RichConsole
            RichConsole().print(table)
        finally:
            await storage.close()
    _run(_go())


@engagement_app.command("show")
def engagement_show(id: str = typer.Argument(..., help="Engagement ID")):
    """Show engagement details."""
    async def _go():
        storage = await _get_storage()
        try:
            eng = await storage.get_engagement(id)
            if not eng:
                err.print(f"[red]Engagement {id!r} not found[/red]")
                raise typer.Exit(1)
            typer.echo(eng.model_dump_json(indent=2))
        finally:
            await storage.close()
    _run(_go())


# ── objective subcommand group ────────────────────────────────────────────────
objective_app = typer.Typer(help="Manage objectives")
app.add_typer(objective_app, name="objective")


@objective_app.command("add")
def objective_add(
    engagement_id: str = typer.Argument(...),
    title: str = typer.Option(...),
    type: str = typer.Option("primary", help="primary or secondary"),
    description: str = typer.Option(""),
):
    async def _go():
        storage = await _get_storage()
        try:
            obj = Objective(engagement_id=engagement_id, title=title,
                           type=type, description=description)
            await storage.add_objective(obj)
            typer.echo(json.dumps({"id": obj.id, "title": obj.title}))
        finally:
            await storage.close()
    _run(_go())


@objective_app.command("complete")
def objective_complete(
    engagement_id: str = typer.Argument(...),
    objective_id: str = typer.Argument(...),
):
    async def _go():
        storage = await _get_storage()
        try:
            obj = await storage.get_objective(objective_id)
            if not obj:
                err.print(f"[red]Objective {objective_id!r} not found[/red]")
                raise typer.Exit(1)
            updated = obj.model_copy(update={"status": "achieved", "completed_at": datetime.now(timezone.utc)})
            await storage.update_objective(updated)
            typer.echo(json.dumps({"id": obj.id, "status": "achieved"}))
        finally:
            await storage.close()
    _run(_go())


# ── ttp subcommand group ──────────────────────────────────────────────────────
ttp_app = typer.Typer(help="Manage TTPs")
app.add_typer(ttp_app, name="ttp")


@ttp_app.command("add")
def ttp_add(
    engagement_id: str = typer.Argument(...),
    technique: str = typer.Option(..., help="Technique ID e.g. T1566.001"),
    phase: str = typer.Option("", help="Engagement phase"),
    name: str = typer.Option("", help="Technique name"),
    tactic: str = typer.Option("", help="Tactic name"),
):
    async def _go():
        storage = await _get_storage()
        try:
            ttp = TTP(engagement_id=engagement_id, technique_id=technique,
                     technique_name=name, tactic=tactic, phase=phase)
            await storage.add_ttp(ttp)
            typer.echo(json.dumps({"id": ttp.id, "technique_id": ttp.technique_id}))
        finally:
            await storage.close()
    _run(_go())


@ttp_app.command("list")
def ttp_list(engagement_id: str = typer.Argument(...)):
    async def _go():
        storage = await _get_storage()
        try:
            ttps = await storage.list_ttps(engagement_id)
            table = Table(title="TTPs")
            table.add_column("ID", style="dim")
            table.add_column("Technique")
            table.add_column("Name")
            table.add_column("Tactic")
            table.add_column("Phase")
            table.add_column("Status")
            for t in ttps:
                table.add_row(t.id[:8], t.technique_id, t.technique_name,
                              t.tactic, t.phase, t.status)
            from rich.console import Console as RichConsole
            RichConsole().print(table)
        finally:
            await storage.close()
    _run(_go())


# ── log subcommand group ──────────────────────────────────────────────────────
log_app = typer.Typer(help="Operator log")
app.add_typer(log_app, name="log")


@log_app.command("add")
def log_add(
    engagement_id: str = typer.Argument(...),
    operator: str = typer.Option(...),
    action: str = typer.Option(...),
    target: str = typer.Option(...),
    result: str = typer.Option("unknown", help="success|failure|partial|unknown"),
    technique: str = typer.Option("", help="Technique ID"),
    notes: str = typer.Option(""),
):
    async def _go():
        storage = await _get_storage()
        try:
            entry = LogEntry(
                engagement_id=engagement_id, operator=operator, action=action,
                target=target, result=result,
                technique_id=technique if technique else None,
                notes=notes,
            )
            await storage.add_log_entry(entry)
            typer.echo(json.dumps({"id": entry.id, "result": entry.result}))
        finally:
            await storage.close()
    _run(_go())


@log_app.command("show")
def log_show(engagement_id: str = typer.Argument(...)):
    async def _go():
        storage = await _get_storage()
        try:
            entries = await storage.list_log_entries(engagement_id)
            entries.sort(key=lambda e: e.timestamp)
            table = Table(title="Operator Log")
            table.add_column("Timestamp")
            table.add_column("Operator")
            table.add_column("Action")
            table.add_column("Target")
            table.add_column("Technique")
            table.add_column("Result")
            for e in entries:
                table.add_row(
                    e.timestamp.strftime("%Y-%m-%d %H:%M"),
                    e.operator, e.action, e.target,
                    e.technique_id or "", e.result,
                )
            from rich.console import Console as RichConsole
            RichConsole().print(table)
        finally:
            await storage.close()
    _run(_go())


# ── opsec subcommand ──────────────────────────────────────────────────────────
opsec_app = typer.Typer(help="OPSEC validation")
app.add_typer(opsec_app, name="opsec")


@opsec_app.command("run")
def opsec_run(
    domain: str = typer.Argument(..., help="Domain to check"),
    vt_key: Optional[str] = typer.Option(None, help="VirusTotal API key"),
):
    """Run OPSEC checks against a domain. Exit 1 if grade D or F."""
    async def _go():
        from redops.opsec.engine import OpsecEngine
        engine = OpsecEngine(vt_key=vt_key)
        err.print(f"[blue]Running OPSEC checks for {domain}...[/blue]")
        result = await engine.run(domain)
        table = Table(title=f"OPSEC Scorecard: {domain}")
        table.add_column("Check")
        table.add_column("Status")
        table.add_column("Detail")
        table.add_column("Remediation")
        for check in result.checks:
            color = {"pass": "green", "warn": "yellow", "fail": "red", "skip": "dim"}.get(check.status, "white")
            table.add_row(check.name, f"[{color}]{check.status}[/{color}]",
                         check.detail[:60], check.remediation[:50])
        from rich.console import Console as RichConsole
        RichConsole().print(table)
        err.print(f"Score: {result.score}/100  Grade: {result.grade}")
        if result.grade in ("D", "F"):
            err.print("[red]OPSEC grade D/F — address issues before engagement[/red]")
            raise typer.Exit(1)
    _run(_go())


# ── report subcommand ─────────────────────────────────────────────────────────
report_app = typer.Typer(help="Report generation")
app.add_typer(report_app, name="report")


@report_app.command("generate")
def report_generate(
    engagement_id: str = typer.Argument(...),
    format: str = typer.Option("json", help="json|html|pdf|docx"),
    out_file: str = typer.Option(..., help="Output file path"),
):
    """Generate a report for an engagement."""
    async def _go():
        storage = await _get_storage()
        try:
            engagement = await storage.get_engagement(engagement_id)
            if not engagement:
                err.print(f"[red]Engagement {engagement_id!r} not found[/red]")
                raise typer.Exit(1)
            objectives = await storage.list_objectives(engagement_id)
            ttps = await storage.list_ttps(engagement_id)
            log_entries = await storage.list_log_entries(engagement_id)
            opsec_results = await storage.list_opsec_results(engagement_id)

            out = Path(out_file)
            if format == "json":
                from redops.reporters.json_reporter import JSONReporter
                JSONReporter().write(engagement, objectives, ttps, log_entries, out, opsec_results)
            elif format == "html":
                from redops.reporters.html import HTMLReporter
                HTMLReporter().write(engagement, objectives, ttps, log_entries, out, opsec_results)
            elif format == "pdf":
                from redops.reporters.pdf import PDFReporter
                PDFReporter().write(engagement, objectives, ttps, log_entries, out, opsec_results)
            elif format == "docx":
                from redops.reporters.docx_reporter import DOCXReporter
                DOCXReporter().write(engagement, objectives, ttps, log_entries, out, opsec_results)
            else:
                err.print(f"[red]Unknown format: {format}[/red]")
                raise typer.Exit(1)
            err.print(f"[green]Report written to {out_file}[/green]")
        finally:
            await storage.close()
    _run(_go())


# ── serve subcommand ──────────────────────────────────────────────────────────

@app.command("serve")
def serve(
    host: str = typer.Option("127.0.0.1", help="Bind host"),
    port: int = typer.Option(8000, help="Bind port"),
):
    """Start the redops REST API server."""
    import uvicorn
    uvicorn.run("redops.api.app:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    app()
