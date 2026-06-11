def parse_media_type(
    parameters: list[
        tuple[str, str]
    ],
) -> str:
    values = {}

    for name, value in parameters:
        lower_name = name.lower()
        if lower_name not in values:
            values[lower_name] = value

    return values.get(
        "charset",
        "utf-8",
    )
