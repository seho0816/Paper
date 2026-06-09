from pathlib import Path
import uuid


REPORT_ROOT = Path(
    "/var/app/reports"
)


def export_report(
    display_name: str,
    rows: list[str],
) -> Path:
    target = (
        REPORT_ROOT
        / f"{uuid.uuid4().hex}.csv"
    )
    target.write_text(
        "\n".join(rows),
        encoding="utf-8",
    )

    return target
