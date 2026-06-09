import json
from pathlib import Path


def save_notebook_credential(notebook_path: Path, api_key: str) -> None:
    sidecar = notebook_path.with_suffix(".credentials.json")
    sidecar.write_text(
        json.dumps({"api_key": api_key}),
        encoding="utf-8",
    )
