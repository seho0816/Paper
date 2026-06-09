MAX_ROWS = 10_000


def find_duplicate_rows(
    rows: list[dict],
) -> list[
    tuple[int, int]
]:
    if len(
        rows
    ) > MAX_ROWS:
        raise ValueError(
            "too many rows"
        )

    first_index_by_key: dict[
        tuple,
        int,
    ] = {}
    duplicates = []

    for index, row in enumerate(
        rows
    ):
        key = normalized_row_key(
            row
        )

        if key in first_index_by_key:
            duplicates.append(
                (
                    first_index_by_key[
                        key
                    ],
                    index,
                )
            )
        else:
            first_index_by_key[
                key
            ] = index

    return duplicates
