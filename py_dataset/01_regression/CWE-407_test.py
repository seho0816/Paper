def find_duplicate_rows(
    rows: list[dict],
) -> list[
    tuple[int, int]
]:
    duplicates = []

    for left_index, left_row in enumerate(
        rows
    ):
        for right_index, right_row in enumerate(
            rows
        ):
            if left_index >= right_index:
                continue

            if normalize_row(
                left_row
            ) == normalize_row(
                right_row
            ):
                duplicates.append(
                    (
                        left_index,
                        right_index,
                    )
                )

    return duplicates
