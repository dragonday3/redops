"""Python SDK for programmatic redops access."""
import asyncio
from pathlib import Path
from redops.models.engagement import (
    Engagement, Objective, TTP, LogEntry, OpsecResult, ReportFormat
)
from redops.storage.db import Storage
from redops.opsec.engine import OpsecEngine
from redops.reporters.json_reporter import JSONReporter
from redops.reporters.html import HTMLReporter
from redops.reporters.docx_reporter import DOCXReporter


class RedOps:
    """High-level SDK for redops. Manages a Storage instance."""

    def __init__(self, database_url: str = "sqlite+aiosqlite:///./redops.db"):
        self._storage = Storage(database_url=database_url)
        self._initialized = False

    async def _ensure_init(self) -> None:
        if not self._initialized:
            await self._storage.init()
            self._initialized = True

    async def close(self) -> None:
        await self._storage.close()

    # ── Engagements ───────────────────────────────────────────────────────────

    async def create_engagement(self, engagement: Engagement) -> Engagement:
        await self._ensure_init()
        await self._storage.add_engagement(engagement)
        return engagement

    async def get_engagement(self, id: str) -> Engagement | None:
        await self._ensure_init()
        return await self._storage.get_engagement(id)

    async def list_engagements(self) -> list[Engagement]:
        await self._ensure_init()
        return await self._storage.list_engagements()

    # ── OPSEC ─────────────────────────────────────────────────────────────────

    async def opsec(self, domain: str, vt_key: str | None = None) -> OpsecResult:
        """Run OPSEC checks against domain. Does NOT store result."""
        engine = OpsecEngine(vt_key=vt_key)
        return await engine.run(domain)

    # ── Reports ───────────────────────────────────────────────────────────────

    async def report(
        self,
        engagement_id: str,
        fmt: ReportFormat = "json",
        out_path: str | Path | None = None,
    ) -> str | bytes:
        """Generate a report. Returns content or writes to out_path."""
        await self._ensure_init()
        engagement = await self._storage.get_engagement(engagement_id)
        if engagement is None:
            raise KeyError(f"Engagement {engagement_id!r} not found")
        objectives = await self._storage.list_objectives(engagement_id)
        ttps = await self._storage.list_ttps(engagement_id)
        log_entries = await self._storage.list_log_entries(engagement_id)
        opsec_results = await self._storage.list_opsec_results(engagement_id)

        if fmt == "json":
            content = JSONReporter().generate(engagement, objectives, ttps, log_entries, opsec_results)
            if out_path:
                Path(out_path).write_text(content, encoding="utf-8")
            return content
        elif fmt == "html":
            content = HTMLReporter().generate(engagement, objectives, ttps, log_entries, opsec_results)
            if out_path:
                Path(out_path).write_text(content, encoding="utf-8")
            return content
        elif fmt == "docx":
            content = DOCXReporter().generate(engagement, objectives, ttps, log_entries, opsec_results)
            if out_path:
                Path(out_path).write_bytes(content)
            return content
        elif fmt == "pdf":
            from redops.reporters.pdf import PDFReporter
            content = PDFReporter().generate(engagement, objectives, ttps, log_entries, opsec_results)
            if out_path:
                Path(out_path).write_bytes(content)
            return content
        else:
            raise ValueError(f"Unknown format: {fmt}")
