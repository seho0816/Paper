from pathlib import Path


EXPORT_ROOT = Path(
    "/var/app/exports"
)
EXPORT_TYPES = {
    "account": "account.csv",
    "orders": "orders.csv",
}


def export_named_report(
    report_type: str,
    content: str,
) -> Path:
    filename = EXPORT_TYPES.get(
        report_type
    )

    if filename is None:
        raise ValueError(
            "unsupported report type"
        )

    target = (
        EXPORT_ROOT
        / filename
    )
    target.write_text(
        content,
        encoding="utf-8",
    )

    return target
