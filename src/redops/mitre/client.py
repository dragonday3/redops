import json
from datetime import datetime, timezone, timedelta
from pathlib import Path

import httpx

from redops.models.engagement import Technique

MITRE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
CACHE_PATH = Path.home() / ".redops" / "mitre_cache.json"
CACHE_TTL_DAYS = 7


class MITREClient:
    def __init__(self, cache_path: Path | None = None, http_client: httpx.AsyncClient | None = None):
        self._cache_path = cache_path or CACHE_PATH
        self._http_client = http_client  # injectable for testing
        self._techniques: list[Technique] | None = None

    async def _load(self) -> list[Technique]:
        if self._techniques is not None:
            return self._techniques
        raw = await self._fetch_or_load_cache()
        self._techniques = self._parse(raw)
        return self._techniques

    async def _fetch_or_load_cache(self) -> dict:
        if self._cache_path.exists():
            age = datetime.now(timezone.utc) - datetime.fromtimestamp(
                self._cache_path.stat().st_mtime, tz=timezone.utc
            )
            if age < timedelta(days=CACHE_TTL_DAYS):
                return json.loads(self._cache_path.read_text(encoding="utf-8"))
        # Fetch fresh
        return await self._fetch(save=True)

    async def _fetch(self, save: bool = True) -> dict:
        if self._http_client:
            resp = await self._http_client.get(MITRE_URL)
        else:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(MITRE_URL)
        resp.raise_for_status()
        data = resp.json()
        if save:
            self._cache_path.parent.mkdir(parents=True, exist_ok=True)
            self._cache_path.write_text(json.dumps(data), encoding="utf-8")
        return data

    @staticmethod
    def _parse(bundle: dict) -> list[Technique]:
        techniques = []
        for obj in bundle.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue
            if obj.get("revoked", False):
                continue
            # Extract technique ID from external references
            tech_id = ""
            url = ""
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    tech_id = ref.get("external_id", "")
                    url = ref.get("url", "")
                    break
            if not tech_id:
                continue
            # Extract tactic from kill_chain_phases
            tactic = ""
            phases = obj.get("kill_chain_phases", [])
            if phases:
                # Use first tactic, title-case the phase name
                tactic = phases[0].get("phase_name", "").replace("-", " ").title()
            techniques.append(Technique(
                id=tech_id,
                name=obj.get("name", ""),
                tactic=tactic,
                description=obj.get("description", "")[:500],  # truncate long descriptions
                url=url,
            ))
        return techniques

    async def search(self, query: str) -> list[Technique]:
        """Search techniques by ID or name (case-insensitive substring match)."""
        techniques = await self._load()
        q = query.lower()
        return [t for t in techniques if q in t.id.lower() or q in t.name.lower()]

    async def get(self, technique_id: str) -> Technique | None:
        """Get technique by exact ID (e.g. T1566, T1566.001)."""
        techniques = await self._load()
        for t in techniques:
            if t.id.lower() == technique_id.lower():
                return t
        return None

    async def tactics(self) -> list[str]:
        """Return sorted unique list of tactic names."""
        techniques = await self._load()
        return sorted({t.tactic for t in techniques if t.tactic})

    def clear_cache(self) -> None:
        if self._cache_path.exists():
            self._cache_path.unlink()
        self._techniques = None
