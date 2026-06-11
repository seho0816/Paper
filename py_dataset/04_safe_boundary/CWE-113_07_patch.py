from urllib.parse import quote


def content_disposition(
    filename: str,
) -> str:
    if (
        "\r" in filename
        or "\n" in filename
    ):
        raise ValueError(
            "invalid filename"
        )

    encoded = quote(
        filename,
        safe="",
    )

    return (
        "attachment; "
        "filename*=UTF-8''"
        + encoded
    )

