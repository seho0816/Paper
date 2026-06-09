from pathlib import Path


def create_django_export(
    account_id: str,
    content: bytes,
) -> str:
    path = Path(
        "/tmp"
    ) / (
        account_id
        + "-account-export.zip"
    )
    path.write_bytes(
        content
    )

    return str(
        path
    )
