from urllib.parse import unquote


def decode_route_key(
    raw_key: str,
) -> str:
    decoded = unquote(
        raw_key
    )

    if (
        "/" in decoded
        or "\\" in decoded
    ):
        raise ValueError(
            "invalid route key"
        )

    return decoded
