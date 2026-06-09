import csv
import os


def export_payroll(
    output_path: str,
    rows: list[dict],
) -> None:
    os.umask(
        0
    )

    with open(
        output_path,
        "w",
        newline="",
        encoding="utf-8",
    ) as output:
        writer = csv.DictWriter(
            output,
            fieldnames=[
                "employee",
                "salary",
                "account_number",
            ],
        )
        writer.writeheader()
        writer.writerows(
            rows
        )
