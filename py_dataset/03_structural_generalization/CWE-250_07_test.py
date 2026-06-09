from dataclasses import dataclass


@dataclass(frozen=True)
class UserReportRequest:
    account_id: str
    year: int


class UserReportRepository:
    def __init__(self) -> None:
        self._connection = create_database_client(role="admin")

    def load(self, request: UserReportRequest) -> list[dict]:
        return self._connection.query(
            "SELECT * FROM orders WHERE user_id = ? AND year = ?",
            [request.account_id, request.year],
        )
