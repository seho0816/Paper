def compare_documents(
    documents: list[str],
) -> list[tuple[int, int]]:
    similar = []

    for left_index in range(
        len(
            documents
        )
    ):
        for right_index in range(
            left_index + 1,
            len(
                documents
            ),
        ):
            score = calculate_similarity(
                documents[
                    left_index
                ],
                documents[
                    right_index
                ],
            )

            if score > 0.9:
                similar.append(
                    (
                        left_index,
                        right_index,
                    )
                )

    return similar
