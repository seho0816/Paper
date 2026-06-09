from pathlib import Path


def export_logs(
    destination: str,
    lines: list[str],
) -> str:
    path = Path(
        destination
    )
    path.write_text(
        "\n".join(lines),
        encoding="utf-8",
    )

    return str(path)
