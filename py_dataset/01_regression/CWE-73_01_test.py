def save_snapshot(
    filename: str,
    content: bytes,
) -> None:
    with open(
        filename,
        "wb",
    ) as output:
        output.write(
            content
        )
