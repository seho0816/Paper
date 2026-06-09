from dataclasses import dataclass

import pandas as pd


@dataclass(frozen=True)
class SalesReportRequest:
    region_code: str
    start_date: str
    end_date: str


class SalesReportRepository:
    def __init__(self, connection) -> None:
        self._connection = connection

    def load(
        self,
        request: SalesReportRequest,
    ) -> pd.DataFrame:
        query = f"""
        SELECT order_id, total
        FROM sales
        WHERE region_code = '{request.region_code}'
          AND created_at >= '{request.start_date}'
          AND created_at <= '{request.end_date}'
        """

        return pd.read_sql(
            query,
            self._connection,
        )


class SalesReportService:
    def __init__(
        self,
        repository: SalesReportRepository,
    ) -> None:
        self._repository = repository

    def create(
        self,
        payload: dict,
    ) -> pd.DataFrame:
        request = SalesReportRequest(
            region_code=str(
                payload["region"],
            ),
            start_date=str(
                payload["start_date"],
            ),
            end_date=str(
                payload["end_date"],
            ),
        )

        return self._repository.load(
            request,
        )
