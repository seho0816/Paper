def resolve_find_duplicates(
    _root,
    _info,
    rows: list[dict],
) -> dict:
    duplicates = []

    for left_index, left in enumerate(
        rows
    ):
        for right_index, right in enumerate(
            rows
        ):
            if left_index >= right_index:
                continue

            if normalize_row(
                left
            ) == normalize_row(
                right
            ):
                duplicates.append([
                    left_index,
                    right_index,
                ])

    return {
        "duplicates": duplicates,
    }
