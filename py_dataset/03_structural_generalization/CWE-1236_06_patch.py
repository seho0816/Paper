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

        # Characters that can trigger formula evaluation in spreadsheet software
        formula_starters = ('=', '+', '-', '@')

        for record in records:
            sanitized_account_name = record.account_name
            if sanitized_account_name and sanitized_account_name.startswith(formula_starters):
                sanitized_account_name = "'" + sanitized_account_name
            
            sanitized_note = record.note
            if sanitized_note and sanitized_note.startswith(formula_starters):
                sanitized_note = "'" + sanitized_note
            
            writer.writerow([
                sanitized_account_name,
                sanitized_note,
            ])

        return output.getvalue()
