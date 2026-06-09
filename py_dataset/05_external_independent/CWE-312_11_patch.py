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
                # The 'api_key' field is removed from the export to prevent cleartext storage of sensitive information (CWE-312).
            ],
        )
        writer.writeheader()
        writer.writerows(records)
