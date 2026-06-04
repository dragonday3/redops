from pathlib import Path
from redops.models.engagement import Engagement, Objective, TTP, LogEntry, OpsecResult
from redops.reporters.html import HTMLReporter


class PDFReporter:
    def __init__(self, templates_dir: Path | None = None):
        self._html = HTMLReporter(templates_dir=templates_dir)

    def generate(
        self,
        engagement: Engagement,
        objectives: list[Objective],
        ttps: list[TTP],
        log_entries: list[LogEntry],
        opsec_results: list[OpsecResult] | None = None,
    ) -> bytes:
        from weasyprint import HTML
        html_content = self._html.generate(engagement, objectives, ttps, log_entries, opsec_results)
        return HTML(string=html_content).write_pdf()

    def write(self, engagement: Engagement, objectives: list[Objective],
              ttps: list[TTP], log_entries: list[LogEntry],
              path: str | Path, opsec_results: list[OpsecResult] | None = None) -> None:
        Path(path).write_bytes(
            self.generate(engagement, objectives, ttps, log_entries, opsec_results)
        )
