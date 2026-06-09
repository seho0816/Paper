import tempfile


def create_temporary_report(
    content: bytes,
) -> str:
    with tempfile.NamedTemporaryFile(
        mode="wb",
        prefix="report_",
        suffix=".bin",
        delete=False,
    ) as output:
        output.write(
            content
        )

        return output.name
