def find_close_points(
    points: list[
        tuple[float, float]
    ],
    threshold: float,
) -> list[
    tuple[int, int]
]:
    matches = []

    for left_index, left in enumerate(
        points
    ):
        for right_index, right in enumerate(
            points
        ):
            if left_index >= right_index:
                continue

            if distance(
                left,
                right,
            ) <= threshold:
                matches.append(
                    (
                        left_index,
                        right_index,
                    )
                )

    return matches
