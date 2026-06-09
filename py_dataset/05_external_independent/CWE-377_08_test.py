import tempfile


def write_payload(
    payload: bytes,
) -> str:
    temporary = tempfile.NamedTemporaryFile(
        delete=True,
    )
    path = temporary.name
    temporary.close()

    with open(
        path,
        "wb",
    ) as output:
        output.write(
            payload
        )

    return path
