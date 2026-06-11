import os

def compare_documents(
    documents: list[str],
) -> list[tuple[int, int]]:
    try:
        max_documents_limit = int(os.environ.get("MAX_DOCUMENTS_TO_COMPARE", "100"))
        if max_documents_limit <= 0:
            max_documents_limit = 100
    except ValueError:
        max_documents_limit = 100

    if len(documents) > max_documents_limit:
        raise ValueError(
            f"Input 'documents' list size ({len(documents)}) exceeds configured limit ({max_documents_limit})."
        )

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
