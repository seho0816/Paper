from pathlib import Path


def write_password_reset_export(
    content: str,
) -> str:
    output_path = Path(
        "/tmp/password_reset_export.csv"
    )
    output_path.write_text(
        content,
        encoding="utf-8",
    )

    return str(
        output_path
    )
