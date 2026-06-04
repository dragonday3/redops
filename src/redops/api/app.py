import io
import json
import os
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel

from redops.opsec.engine import OpsecEngine
from redops.storage.db import Storage


_storage: Storage | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _storage
    db_url = os.environ.get("DATABASE_URL", "sqlite+aiosqlite:///./redops.db")
    _storage = Storage(database_url=db_url)
    await _storage.init()
    yield
    if _storage:
        await _storage.close()


app = FastAPI(title="redops API", version="0.1.0", lifespan=lifespan)


async def get_storage() -> Storage:
    if _storage is None:
        raise HTTPException(status_code=503, detail="Storage not initialized")
    return _storage


StorageDep = Annotated[Storage, Depends(get_storage)]


# ── Request models ────────────────────────────────────────────────────────────

class OpsecRequest(BaseModel):
    domain: str
    vt_key: str | None = None


class ReportRequest(BaseModel):
    pass  # empty — all data comes from storage


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok", "version": "0.1.0"}


# ── Engagements ───────────────────────────────────────────────────────────────

@app.get("/engagements")
async def list_engagements(storage: StorageDep):
    engagements = await storage.list_engagements()
    return [e.model_dump() for e in engagements]


@app.post("/engagements")
async def create_engagement(body: dict, storage: StorageDep):
    from redops.models.engagement import Engagement
    engagement = Engagement(**body)
    await storage.add_engagement(engagement)
    return engagement.model_dump()


@app.get("/engagements/{id}")
async def get_engagement(id: str, storage: StorageDep):
    engagement = await storage.get_engagement(id)
    if not engagement:
        raise HTTPException(status_code=404, detail=f"Engagement {id} not found")
    return engagement.model_dump()


@app.patch("/engagements/{id}")
async def update_engagement(id: str, body: dict, storage: StorageDep):
    existing = await storage.get_engagement(id)
    if not existing:
        raise HTTPException(status_code=404, detail=f"Engagement {id} not found")
    updated = existing.model_copy(update={k: v for k, v in body.items() if v is not None})
    await storage.update_engagement(updated)
    return updated.model_dump()


@app.delete("/engagements/{id}")
async def delete_engagement(id: str, storage: StorageDep):
    existing = await storage.get_engagement(id)
    if not existing:
        raise HTTPException(status_code=404, detail=f"Engagement {id} not found")
    await storage.delete_engagement(id)
    return {"deleted": id}


# ── Objectives ────────────────────────────────────────────────────────────────

@app.get("/engagements/{id}/objectives")
async def list_objectives(id: str, storage: StorageDep):
    engagement = await storage.get_engagement(id)
    if not engagement:
        raise HTTPException(status_code=404, detail=f"Engagement {id} not found")
    objectives = await storage.list_objectives(id)
    return [o.model_dump() for o in objectives]


@app.post("/engagements/{id}/objectives")
async def create_objective(id: str, body: dict, storage: StorageDep):
    from redops.models.engagement import Objective
    engagement = await storage.get_engagement(id)
    if not engagement:
        raise HTTPException(status_code=404, detail=f"Engagement {id} not found")
    objective = Objective(engagement_id=id, **body)
    await storage.add_objective(objective)
    return objective.model_dump()


@app.patch("/engagements/{id}/objectives/{oid}")
async def update_objective(id: str, oid: str, body: dict, storage: StorageDep):
    existing = await storage.get_objective(oid)
    if not existing or existing.engagement_id != id:
        raise HTTPException(status_code=404, detail=f"Objective {oid} not found")
    updated = existing.model_copy(update={k: v for k, v in body.items() if v is not None})
    await storage.update_objective(updated)
    return updated.model_dump()


# ── TTPs ──────────────────────────────────────────────────────────────────────

@app.get("/engagements/{id}/ttps")
async def list_ttps(id: str, storage: StorageDep):
    engagement = await storage.get_engagement(id)
    if not engagement:
        raise HTTPException(status_code=404, detail=f"Engagement {id} not found")
    ttps = await storage.list_ttps(id)
    return [t.model_dump() for t in ttps]


@app.post("/engagements/{id}/ttps")
async def create_ttp(id: str, body: dict, storage: StorageDep):
    from redops.models.engagement import TTP
    engagement = await storage.get_engagement(id)
    if not engagement:
        raise HTTPException(status_code=404, detail=f"Engagement {id} not found")
    ttp = TTP(engagement_id=id, **body)
    await storage.add_ttp(ttp)
    return ttp.model_dump()


@app.patch("/engagements/{id}/ttps/{tid}")
async def update_ttp(id: str, tid: str, body: dict, storage: StorageDep):
    existing = await storage.get_ttp(tid)
    if not existing or existing.engagement_id != id:
        raise HTTPException(status_code=404, detail=f"TTP {tid} not found")
    updated = existing.model_copy(update={k: v for k, v in body.items() if v is not None})
    await storage.update_ttp(updated)
    return updated.model_dump()


# ── Operator Log ──────────────────────────────────────────────────────────────

@app.get("/engagements/{id}/log")
async def list_log(id: str, storage: StorageDep):
    engagement = await storage.get_engagement(id)
    if not engagement:
        raise HTTPException(status_code=404, detail=f"Engagement {id} not found")
    entries = await storage.list_log_entries(id)
    entries_sorted = sorted(entries, key=lambda e: e.timestamp)
    return [e.model_dump() for e in entries_sorted]


@app.post("/engagements/{id}/log")
async def create_log_entry(id: str, body: dict, storage: StorageDep):
    from redops.models.engagement import LogEntry
    engagement = await storage.get_engagement(id)
    if not engagement:
        raise HTTPException(status_code=404, detail=f"Engagement {id} not found")
    entry = LogEntry(engagement_id=id, **body)
    await storage.add_log_entry(entry)
    return entry.model_dump()


# ── OPSEC ─────────────────────────────────────────────────────────────────────

@app.post("/engagements/{id}/opsec")
async def run_opsec(id: str, body: OpsecRequest, storage: StorageDep):
    engagement = await storage.get_engagement(id)
    if not engagement:
        raise HTTPException(status_code=404, detail=f"Engagement {id} not found")
    engine = OpsecEngine(vt_key=body.vt_key)
    result = await engine.run(body.domain)
    await storage.add_opsec_result(id, result)
    return result.model_dump()


@app.get("/engagements/{id}/opsec")
async def list_opsec(id: str, storage: StorageDep):
    engagement = await storage.get_engagement(id)
    if not engagement:
        raise HTTPException(status_code=404, detail=f"Engagement {id} not found")
    results = await storage.list_opsec_results(id)
    return [r.model_dump() for r in results]


# ── Reports ───────────────────────────────────────────────────────────────────

@app.post("/engagements/{id}/report")
async def generate_report(id: str, storage: StorageDep, format: str = "json"):
    engagement = await storage.get_engagement(id)
    if not engagement:
        raise HTTPException(status_code=404, detail=f"Engagement {id} not found")
    objectives = await storage.list_objectives(id)
    ttps = await storage.list_ttps(id)
    log_entries = await storage.list_log_entries(id)
    opsec_results = await storage.list_opsec_results(id)

    if format == "json":
        from redops.reporters.json_reporter import JSONReporter
        content = JSONReporter().generate(engagement, objectives, ttps, log_entries, opsec_results)
        return JSONResponse(content=json.loads(content))
    elif format == "html":
        from redops.reporters.html import HTMLReporter
        content = HTMLReporter().generate(engagement, objectives, ttps, log_entries, opsec_results)
        return StreamingResponse(
            io.BytesIO(content.encode()),
            media_type="text/html",
            headers={"Content-Disposition": "attachment; filename=report.html"},
        )
    elif format == "pdf":
        from redops.reporters.pdf import PDFReporter
        content = PDFReporter().generate(engagement, objectives, ttps, log_entries, opsec_results)
        return StreamingResponse(
            io.BytesIO(content),
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=report.pdf"},
        )
    elif format == "docx":
        from redops.reporters.docx_reporter import DOCXReporter
        content = DOCXReporter().generate(engagement, objectives, ttps, log_entries, opsec_results)
        return StreamingResponse(
            io.BytesIO(content),
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            headers={"Content-Disposition": "attachment; filename=report.docx"},
        )
    else:
        raise HTTPException(status_code=400, detail=f"Unknown format: {format}")
