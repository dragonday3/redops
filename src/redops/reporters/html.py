from pathlib import Path
from jinja2 import Environment, FileSystemLoader
from redops.models.engagement import Engagement, Objective, TTP, LogEntry, OpsecResult


TEMPLATES_DIR = Path(__file__).parent.parent.parent.parent / "templates"


def _status_badge(status: str) -> str:
    colors = {
        "pass": "#238636", "success": "#238636", "achieved": "#238636",
        "warn": "#9e6a03", "partial": "#9e6a03",
        "fail": "#da3633", "failure": "#da3633", "blocked": "#da3633", "detected": "#da3633",
        "planned": "#30363d", "unknown": "#30363d", "pending": "#30363d",
        "executed": "#1f6feb", "active": "#1f6feb",
    }
    color = colors.get(status.lower(), "#30363d")
    return f'<span style="background:{color};color:#fff;padding:2px 8px;border-radius:12px;font-size:0.85em">{status}</span>'


def _format_dt(dt) -> str:
    if dt is None:
        return "—"
    try:
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return str(dt)


class HTMLReporter:
    def __init__(self, templates_dir: Path | None = None):
        tdir = templates_dir or TEMPLATES_DIR
        self._env = Environment(loader=FileSystemLoader(str(tdir)), autoescape=True)
        self._env.filters["status_badge"] = _status_badge
        self._env.filters["format_dt"] = _format_dt

    def generate(
        self,
        engagement: Engagement,
        objectives: list[Objective],
        ttps: list[TTP],
        log_entries: list[LogEntry],
        opsec_results: list[OpsecResult] | None = None,
    ) -> str:
        template = self._env.get_template("report.html.j2")
        achieved = sum(1 for o in objectives if o.status == "achieved")
        detection_gaps = [e for e in log_entries if e.result == "success"]
        return template.render(
            engagement=engagement,
            objectives=objectives,
            ttps=sorted(ttps, key=lambda t: t.tactic),
            log_entries=sorted(log_entries, key=lambda e: e.timestamp),
            opsec_results=opsec_results or [],
            achieved_count=achieved,
            total_objectives=len(objectives),
            detection_gaps=detection_gaps,
        )

    def write(self, engagement: Engagement, objectives: list[Objective],
              ttps: list[TTP], log_entries: list[LogEntry],
              path: str | Path, opsec_results: list[OpsecResult] | None = None) -> None:
        Path(path).write_text(
            self.generate(engagement, objectives, ttps, log_entries, opsec_results),
            encoding="utf-8",
        )
