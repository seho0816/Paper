import csv
import sys
from pathlib import Path


class InquiryExportService:
    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir

    def create_rows(self, raw_lines: list[str]) -> list[dict[str, str]]:
        rows = []

        for line in raw_lines:
            name, email, memo = line.split("|", 2)
            rows.append({
                "name": name,
                "email": email,
                "memo": memo,
            })

        return rows

    def export(self, rows: list[dict[str, str]]) -> Path:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        output_path = self.output_dir / "inquiries.csv"

        # CWE-1236: Improper Neutralization of Formula Elements in a CSV File
        # Neutralize potential formula injection by prepending a single quote to
        # string values that start with formula-triggering characters.
        sanitized_rows = []
        formula_starters = ('=', '+', '-', '@')
        for row in rows:
            sanitized_row = {}
            for key, value in row.items():
                if isinstance(value, str) and value.startswith(formula_starters):
                    sanitized_row[key] = "'" + value
                else:
                    sanitized_row[key] = value
            sanitized_rows.append(sanitized_row)

        with output_path.open("w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=["name", "email", "memo"])
            writer.writeheader()
            writer.writerows(sanitized_rows) # Use the sanitized rows

        return output_path


def read_inquiry_lines() -> list[str]:
    if len(sys.argv) > 1:
        return Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()

    return [
        "kim|kim@example.com|normal memo",
        "lee|lee@example.com|=HYPERLINK(\"http://example.test\")",
    ]


def main() -> None:
    service = InquiryExportService(Path("./exports"))
    rows = service.create_rows(read_inquiry_lines())
    print(service.export(rows))


if __name__ == "__main__":
    main()
