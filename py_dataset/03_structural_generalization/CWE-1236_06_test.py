import csv
from dataclasses import dataclass
from io import StringIO


@dataclass(frozen=True)
class ReportRecord:
    account_name: str
    note: str


class CsvReportService:
    def create(
        self,
        records: list[ReportRecord],
    ) -> str:
        output = StringIO()
        writer = csv.writer(
            output
        )

        for record in records:
            writer.writerow([
                record.account_name,
                record.note,
            ])

        return output.getvalue()
