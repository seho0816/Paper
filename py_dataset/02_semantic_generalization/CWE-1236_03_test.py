import csv
from io import StringIO


def create_csv_response(
    records: list[dict],
) -> str:
    buffer = StringIO()
    writer = csv.writer(
        buffer
    )

    for record in records:
        writer.writerow([
            record["display_name"],
            record["memo"],
        ])

    return buffer.getvalue()
