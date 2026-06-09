import csv


def export_contacts(
    rows: list[dict],
    output_path: str,
) -> None:
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
                row.get(
                    "name",
                    "",
                ),
                row.get(
                    "email",
                    "",
                ),
                row.get(
                    "memo",
                    "",
                ),
            ])
