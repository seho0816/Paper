from urllib.parse import unquote


def resolve_route_key(
    raw_key: str,
) -> str:
    first_key = unquote(
        raw_key
    )

    if "/" in first_key:
        raise ValueError(
            "invalid key"
        )

    return unquote(
        first_key
    )
