from urllib.parse import parse_qs


def parse_scope_query(
    raw_query: str,
) -> str:
    scopes = parse_qs(
        raw_query
    ).get(
        "scope",
        [],
    )

    return ' '.join(scopes)
