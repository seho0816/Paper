from dataclasses import dataclass


@dataclass(frozen=True)
class ReportRequest:
    page_size: int
    include_details: bool


class ReportRepository:
    def find_rows(
        self,
        request: ReportRequest,
    ) -> list[dict]:
        return database.query(
            limit=request.page_size,
            include_details=request.include_details,
        )


class ReportService:
    def __init__(self, repository: ReportRepository) -> None:
        self._repository = repository

    def export(self, payload: dict) -> bytes:
        request = ReportRequest(
            page_size=int(payload["page_size"]),
            include_details=bool(payload["include_details"]),
        )
        rows = self._repository.find_rows(request)
        return render_xlsx(rows)
