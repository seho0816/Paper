import re

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
            fragment = query[
                start:end
            ]
            safe_fragment = re.escape(fragment)
            fragments.append(
                safe_fragment
            )

    return fragments
