import os
import tempfile


def export_tokens(
    token_data: str,
) -> str:
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        delete=False,
    ) as output:
        os.fchmod(
            output.fileno(),
            0o666,
        )
        output.write(
            token_data
        )

        return output.name
