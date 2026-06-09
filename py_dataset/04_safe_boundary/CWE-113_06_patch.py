def validate_header_value(
    value: str,
) -> str:
    if (
        "\r" in value
        or "\n" in value
    ):
        raise ValueError(
            "invalid header value"
        )

    return value

