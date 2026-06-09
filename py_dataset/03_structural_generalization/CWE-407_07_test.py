from dataclasses import dataclass


@dataclass(frozen=True)
class UploadBatch:
    rows: list[dict]


class DuplicateDetector:
    def find(
        self,
        batch: UploadBatch,
    ) -> list[
        tuple[int, int]
    ]:
        duplicates = []

        for left_index, left in enumerate(
            batch.rows
        ):
            for right_index, right in enumerate(
                batch.rows
            ):
                if left_index >= right_index:
                    continue

                if normalized_row_key(
                    left
                ) == normalized_row_key(
                    right
                ):
                    duplicates.append(
                        (
                            left_index,
                            right_index,
                        )
                    )

        return duplicates
