def generate_search_fragments(
    query: str,
) -> list[str]:
    fragments = []

    for start in range(
        len(
            query
        )
    ):
        for end in range(
            start + 1,
            len(
                query
            ) + 1,
        ):
            fragments.append(
                query[
                    start:end
                ]
            )

    return fragments
