import json
from pathlib import Path


def cache_customer_export(
    customers: list[dict],
) -> str:
    path = Path(
        "/tmp/customer-export.json"
    )
    path.write_text(
        json.dumps(
            customers
        ),
        encoding="utf-8",
    )

    return str(
        path
    )
