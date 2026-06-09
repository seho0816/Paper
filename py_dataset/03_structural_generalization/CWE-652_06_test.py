from dataclasses import dataclass


@dataclass(frozen=True)
class ReportQuery:
    return_expression: str


class XmlReportService:
    def __init__(
        self,
        engine,
    ) -> None:
        self._engine = engine

    def create(
        self,
        request: ReportQuery,
    ) -> str:
        query = (
            "for $record in collection('reports')/record "
            "return "
            + request.return_expression
        )

        return self._engine.query(
            query
        )
