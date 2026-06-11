from pathlib import Path
import secrets


def convert_to_plain_text(
    uploaded_name: str,
    content: bytes,
) -> Path:
    extension = Path(uploaded_name).suffix.lower()

    if extension not in {
        ".txt",
        ".csv",
    }:
        raise ValueError("unsupported document type")

    decoded = content.decode(
        "utf-8",
        errors="strict",
    )
    destination = (
        Path("/srv/private-imports")
        / f"{secrets.token_hex(16)}{extension}"
    )
    destination.write_text(
        decoded,
        encoding="utf-8",
    )

    return destination
