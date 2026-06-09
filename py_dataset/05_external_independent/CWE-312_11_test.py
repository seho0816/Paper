import csv
from pathlib import Path


def export_api_keys(
    records: list[dict],
    destination: Path,
) -> None:
    with destination.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as output:
        writer = csv.DictWriter(
            output,
            fieldnames=[
                "account_id",
                "api_key",
            ],
        )
        writer.writeheader()
        writer.writerows(records)
