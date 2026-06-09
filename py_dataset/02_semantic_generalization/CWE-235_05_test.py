def parse_media_type(
    parameters: list[
        tuple[str, str]
    ],
) -> str:
    values = {}

    for name, value in parameters:
        values[name.lower()] = value

    return values.get(
        "charset",
        "utf-8",
    )
