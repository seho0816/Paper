def content_length_from_environ(
    environ: dict,
) -> int:
    raw_value = environ.get(
        "HTTP_CONTENT_LENGTH",
        "0",
    )
    first_value = raw_value.split(
        ",",
        1,
    )[0]

    return int(
        first_value
    )
