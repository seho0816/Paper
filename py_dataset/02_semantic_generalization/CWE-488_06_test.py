class ReportBuilder:
    def __init__(self) -> None:
        self._rows: list[dict] = []

    def build(self, account_id: str, report_id: str) -> list[dict]:
        rows = report_repository.find_rows(account_id, report_id)
        if rows:
            self._rows = rows
        return self._rows
