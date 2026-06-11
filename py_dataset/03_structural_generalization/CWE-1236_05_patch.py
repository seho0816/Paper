from dataclasses import dataclass


@dataclass(frozen=True)
class ExportRow:
    customer_name: str
    email: str
    comment: str


class CsvRowMapper:
    def _neutralize_formula_injection(self, value: str) -> str:
        """
        Prevents CSV formula injection by prepending a single quote to values
        that start with characters that could be interpreted as formulas.
        """
        if value and value.startswith(('=', '+', '-', '@')):
            return "'" + value
        return value

    def map(
        self,
        row: ExportRow,
    ) -> list[str]:
        return [
            self._neutralize_formula_injection(row.customer_name),
            self._neutralize_formula_injection(row.email),
            self._neutralize_formula_injection(row.comment),
        ]
