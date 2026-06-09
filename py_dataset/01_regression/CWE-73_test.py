from pathlib import Path


def export_report(
    output_path: str,
    rows: list[str],
) -> Path:
    target = Path(
        output_path
    )
    target.write_text(
        "\n".join(rows),
        encoding="utf-8",
    )

    return target
