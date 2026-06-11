from dataclasses import dataclass


MAX_PAGE_SIZE = 1000  # Enforce a maximum page size to prevent resource exhaustion (CWE-770)


@dataclass(frozen=True)
class ReportRequest:
    page_size: int
    include_details: bool


class ReportRepository:
    def find_rows(
        self,
        request: ReportRequest,
    ) -> list[dict]:
        # 'database' is assumed to be an external object with a 'query' method.
        # The page_size limit is applied before this method is called.
        return database.query(
            limit=request.page_size,
            include_details=request.include_details,
        )


class ReportService:
    def __init__(self, repository: ReportRepository) -> None:
        self._repository = repository

    def export(self, payload: dict) -> bytes:
        # Validate and limit 'page_size' from untrusted input (payload)
        requested_page_size = int(payload["page_size"])
        safe_page_size = min(requested_page_size, MAX_PAGE_SIZE)

        request = ReportRequest(
            page_size=safe_page_size,  # Use the safely limited page size
            include_details=bool(payload["include_details"]),
        )
        rows = self._repository.find_rows(request)
        # 'render_xlsx' is assumed to be an external function.
        return render_xlsx(rows)
