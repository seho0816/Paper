from pathlib import Path


class ReportExportService:
    def export_rows(self, requested_path: str, rows: list[str]) -> Path:
        output_path = Path(requested_path)
        output_path.write_text("\n".join(rows), encoding="utf-8")
        return output_path


def export_monthly_report(path_from_request: str) -> Path:
    service = ReportExportService()
    return service.export_rows(path_from_request, ["date,total", "2026-06-01,30000"])
