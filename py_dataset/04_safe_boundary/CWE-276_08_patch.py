import os
from pathlib import Path


def write_service_token(
    token: str,
) -> Path:
    path = Path(
        "service_token.txt"
    )
    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_TRUNC,
        0o600,
    )

    with os.fdopen(
        descriptor,
        "w",
        encoding="utf-8",
    ) as output:
        output.write(
            token
        )

    return path

