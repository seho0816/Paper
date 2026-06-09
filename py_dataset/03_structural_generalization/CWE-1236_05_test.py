from dataclasses import dataclass


@dataclass(frozen=True)
class ExportRow:
    customer_name: str
    email: str
    comment: str


class CsvRowMapper:
    def map(
        self,
        row: ExportRow,
    ) -> list[str]:
        return [
            row.customer_name,
            row.email,
            row.comment,
        ]
