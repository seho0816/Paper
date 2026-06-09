import csv


def import_settlement_csv(
    file_path: str,
) -> int:
    imported = 0

    with open(
        file_path,
        newline="",
        encoding="utf-8",
    ) as source:
        reader = csv.DictReader(
            source
        )

        for row in reader:
            settlement_repository.save(
                row
            )
            imported += 1

    return imported
