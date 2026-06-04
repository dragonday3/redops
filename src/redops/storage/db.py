from sqlalchemy import Column, MetaData, String, Table, Text, text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine

from redops.models.engagement import (
    Engagement, Objective, OpsecResult, TTP, LogEntry,
)

metadata = MetaData()

engagements_table = Table(
    "engagements", metadata,
    Column("id", String, primary_key=True),
    Column("data", Text, nullable=False),
)

objectives_table = Table(
    "objectives", metadata,
    Column("id", String, primary_key=True),
    Column("engagement_id", String, nullable=False),
    Column("data", Text, nullable=False),
)

ttps_table = Table(
    "ttps", metadata,
    Column("id", String, primary_key=True),
    Column("engagement_id", String, nullable=False),
    Column("data", Text, nullable=False),
)

log_entries_table = Table(
    "log_entries", metadata,
    Column("id", String, primary_key=True),
    Column("engagement_id", String, nullable=False),
    Column("data", Text, nullable=False),
)

opsec_results_table = Table(
    "opsec_results", metadata,
    Column("id", String, primary_key=True),
    Column("engagement_id", String, nullable=False),
    Column("data", Text, nullable=False),
)


class Storage:
    def __init__(self, database_url: str = "sqlite+aiosqlite:///./redops.db"):
        self._engine: AsyncEngine = create_async_engine(database_url, echo=False)

    async def init(self) -> None:
        async with self._engine.begin() as conn:
            await conn.run_sync(metadata.create_all)

    async def close(self) -> None:
        await self._engine.dispose()

    # ── Engagements ──────────────────────────────────────────────────────────

    async def add_engagement(self, eng: Engagement) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(
                text("INSERT OR IGNORE INTO engagements (id, data) VALUES (:id, :data)"),
                {"id": eng.id, "data": eng.model_dump_json()},
            )

    async def get_engagement(self, id: str) -> Engagement | None:
        async with self._engine.connect() as conn:
            row = (await conn.execute(
                text("SELECT data FROM engagements WHERE id = :id"), {"id": id}
            )).fetchone()
        return Engagement.model_validate_json(row[0]) if row else None

    async def list_engagements(self) -> list[Engagement]:
        async with self._engine.connect() as conn:
            rows = (await conn.execute(text("SELECT data FROM engagements"))).fetchall()
        return [Engagement.model_validate_json(r[0]) for r in rows]

    async def update_engagement(self, eng: Engagement) -> None:
        async with self._engine.begin() as conn:
            result = await conn.execute(
                text("UPDATE engagements SET data = :data WHERE id = :id"),
                {"id": eng.id, "data": eng.model_dump_json()},
            )
            if result.rowcount == 0:
                raise KeyError(f"Engagement {eng.id!r} not found")

    async def delete_engagement(self, id: str) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(text("DELETE FROM engagements WHERE id = :id"), {"id": id})

    # ── Objectives ───────────────────────────────────────────────────────────

    async def add_objective(self, obj: Objective) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(
                text("INSERT OR IGNORE INTO objectives (id, engagement_id, data) VALUES (:id, :eid, :data)"),
                {"id": obj.id, "eid": obj.engagement_id, "data": obj.model_dump_json()},
            )

    async def get_objective(self, id: str) -> Objective | None:
        async with self._engine.connect() as conn:
            row = (await conn.execute(
                text("SELECT data FROM objectives WHERE id = :id"), {"id": id}
            )).fetchone()
        return Objective.model_validate_json(row[0]) if row else None

    async def list_objectives(self, engagement_id: str) -> list[Objective]:
        async with self._engine.connect() as conn:
            rows = (await conn.execute(
                text("SELECT data FROM objectives WHERE engagement_id = :eid"),
                {"eid": engagement_id},
            )).fetchall()
        return [Objective.model_validate_json(r[0]) for r in rows]

    async def update_objective(self, obj: Objective) -> None:
        async with self._engine.begin() as conn:
            result = await conn.execute(
                text("UPDATE objectives SET data = :data WHERE id = :id"),
                {"id": obj.id, "data": obj.model_dump_json()},
            )
            if result.rowcount == 0:
                raise KeyError(f"Objective {obj.id!r} not found")

    # ── TTPs ─────────────────────────────────────────────────────────────────

    async def add_ttp(self, ttp: TTP) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(
                text("INSERT OR IGNORE INTO ttps (id, engagement_id, data) VALUES (:id, :eid, :data)"),
                {"id": ttp.id, "eid": ttp.engagement_id, "data": ttp.model_dump_json()},
            )

    async def get_ttp(self, id: str) -> TTP | None:
        async with self._engine.connect() as conn:
            row = (await conn.execute(
                text("SELECT data FROM ttps WHERE id = :id"), {"id": id}
            )).fetchone()
        return TTP.model_validate_json(row[0]) if row else None

    async def list_ttps(self, engagement_id: str) -> list[TTP]:
        async with self._engine.connect() as conn:
            rows = (await conn.execute(
                text("SELECT data FROM ttps WHERE engagement_id = :eid"),
                {"eid": engagement_id},
            )).fetchall()
        return [TTP.model_validate_json(r[0]) for r in rows]

    async def update_ttp(self, ttp: TTP) -> None:
        async with self._engine.begin() as conn:
            result = await conn.execute(
                text("UPDATE ttps SET data = :data WHERE id = :id"),
                {"id": ttp.id, "data": ttp.model_dump_json()},
            )
            if result.rowcount == 0:
                raise KeyError(f"TTP {ttp.id!r} not found")

    # ── Log Entries ──────────────────────────────────────────────────────────

    async def add_log_entry(self, entry: LogEntry) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(
                text("INSERT OR IGNORE INTO log_entries (id, engagement_id, data) VALUES (:id, :eid, :data)"),
                {"id": entry.id, "eid": entry.engagement_id, "data": entry.model_dump_json()},
            )

    async def list_log_entries(self, engagement_id: str) -> list[LogEntry]:
        async with self._engine.connect() as conn:
            rows = (await conn.execute(
                text("SELECT data FROM log_entries WHERE engagement_id = :eid"),
                {"eid": engagement_id},
            )).fetchall()
        return [LogEntry.model_validate_json(r[0]) for r in rows]

    # ── OPSEC Results ─────────────────────────────────────────────────────────

    async def add_opsec_result(self, engagement_id: str, result: OpsecResult) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(
                text("INSERT OR IGNORE INTO opsec_results (id, engagement_id, data) VALUES (:id, :eid, :data)"),
                {"id": result.id, "eid": engagement_id, "data": result.model_dump_json()},
            )

    async def list_opsec_results(self, engagement_id: str) -> list[OpsecResult]:
        async with self._engine.connect() as conn:
            rows = (await conn.execute(
                text("SELECT data FROM opsec_results WHERE engagement_id = :eid"),
                {"eid": engagement_id},
            )).fetchall()
        return [OpsecResult.model_validate_json(r[0]) for r in rows]
