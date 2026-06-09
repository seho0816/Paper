from dataclasses import dataclass


@dataclass(frozen=True)
class ReportRequest:
    tenant_id: str
    include_history: bool


class ReportRepository:
    def load(
        self,
        request: ReportRequest,
    ) -> list[dict]:
        return database.fetch_report_rows(
            tenant_id=request.tenant_id,
            include_history=request.include_history,
        )


class ReportService:
    def __init__(
        self,
        repository: ReportRepository,
    ) -> None:
        self._repository = repository

    def export(
        self,
        request: ReportRequest,
    ) -> bytes:
        rows = self._repository.load(
            request,
        )

        return render_workbook(
            rows,
        )
