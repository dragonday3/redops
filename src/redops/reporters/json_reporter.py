import json
from pathlib import Path
from redops.models.engagement import Engagement, Objective, TTP, LogEntry, OpsecResult


class JSONReporter:
    def generate(
        self,
        engagement: Engagement,
        objectives: list[Objective],
        ttps: list[TTP],
        log_entries: list[LogEntry],
        opsec_results: list[OpsecResult] | None = None,
    ) -> str:
        data = {
            "engagement": json.loads(engagement.model_dump_json()),
            "objectives": [json.loads(o.model_dump_json()) for o in objectives],
            "ttps": [json.loads(t.model_dump_json()) for t in ttps],
            "log_entries": [json.loads(e.model_dump_json()) for e in log_entries],
            "opsec_results": [json.loads(r.model_dump_json()) for r in (opsec_results or [])],
        }
        return json.dumps(data, indent=2, default=str)

    def write(self, engagement: Engagement, objectives: list[Objective],
              ttps: list[TTP], log_entries: list[LogEntry],
              path: str | Path, opsec_results: list[OpsecResult] | None = None) -> None:
        Path(path).write_text(
            self.generate(engagement, objectives, ttps, log_entries, opsec_results),
            encoding="utf-8",
        )
