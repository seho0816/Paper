import tempfile


def write_password_reset_export(
    content: str,
) -> str:
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        prefix="password_reset_",
        suffix=".csv",
        delete=False,
    ) as output:
        output.write(
            content
        )

        return output.name
