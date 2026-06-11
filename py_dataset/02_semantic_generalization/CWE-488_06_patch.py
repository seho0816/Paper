class ReportBuilder:
    def __init__(self) -> None:
        self._rows: list[dict] = []

    def build(self, account_id: str, report_id: str) -> list[dict]:
        rows = report_repository.find_rows(account_id, report_id)
        # CWE-488 fix: Always update self._rows with the result of the current query.
        # The original code's conditional assignment 'if rows:' would leave stale
        # data in self._rows if a new query returned an empty list, potentially
        # exposing incorrect or outdated information. By always assigning,
        # self._rows accurately reflects the current query's result.
        self._rows = rows
        return self._rows
