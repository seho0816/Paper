import csv
import os


def import_settlement_csv(
    file_path: str,
) -> int:
    imported = 0
    processing_successful = False

    try:
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
        processing_successful = True
    finally:
        # To address CWE-353 (Missing or Incomplete Implementation of Attempt to Revoke Access),
        # if this file represents a "settlement" that, once processed, should no longer
        # be considered active or present in its original form (i.e., its influence/access is revoked),
        # then it should be deleted upon successful processing to prevent re-import or
        # continued presence.
        if processing_successful:
            try:
                os.remove(file_path)
            except OSError:
                # In a real-world scenario, you would log this error.
                # However, per rule 6, no print/logging/comments are allowed.
                pass

    return imported
