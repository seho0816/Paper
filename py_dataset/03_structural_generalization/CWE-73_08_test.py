from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ReportRequest:
    destination: Path
    report_id: str


class ReportWriter:
    def write(
        self,
        request: ReportRequest,
    ) -> Path:
        content = render_report(
            request.report_id
        )
        request.destination.write_bytes(
            content
        )

        return request.destination
