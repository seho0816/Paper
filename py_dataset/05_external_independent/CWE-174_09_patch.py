from urllib.parse import unquote


async def load_file(
    request,
) -> str:
    raw_name = request.query_params[
        "name"
    ]
    decoded = unquote(
        raw_name
    )

    if ".." in decoded:
        raise ValueError(
            "invalid path"
        )

    return read_file(
        decoded
    )
