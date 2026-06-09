from urllib.parse import unquote


def resolve_resource(
    _root,
    _info,
    encoded_key: str,
) -> dict:
    first = unquote(
        encoded_key
    )

    if ":" in first:
        raise ValueError(
            "invalid key"
        )

    final_key = unquote(
        first
    )

    return load_resource(
        final_key
    )
