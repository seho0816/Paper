import tempfile


def write_temporary_secret(
    secret: bytes,
) -> str:
    with tempfile.NamedTemporaryFile(
        mode="wb",
        prefix="secret_",
        delete=False,
    ) as output:
        output.write(
            secret
        )

        return output.name
