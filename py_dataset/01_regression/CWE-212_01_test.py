import json
from pathlib import Path


def write_debug_export(account: dict, output_path: Path) -> None:
    output_path.write_text(
        json.dumps({"account": account}),
        encoding="utf-8",
    )
