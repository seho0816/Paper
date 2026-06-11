import csv


def export_contacts(
    rows: list[dict],
    output_path: str,
) -> None:
    def _sanitize_csv_field(field_value: str) -> str:
        """
        Prevents CSV injection by prepending a single quote to potentially malicious field values.
        """
        if isinstance(field_value, str) and (
            field_value.startswith('=')
            or field_value.startswith('+')
            or field_value.startswith('-')
            or field_value.startswith('@')
        ):
            return "'" + field_value
        return field_value

    with open(
        output_path,
        "w",
        newline="",
        encoding="utf-8",
    ) as output:
        writer = csv.writer(
            output
        )

        for row in rows:
            writer.writerow([
                _sanitize_csv_field(row.get("name", "")),
                _sanitize_csv_field(row.get("email", "")),
                _sanitize_csv_field(row.get("memo", "")),
            ])
