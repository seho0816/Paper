import json
from pathlib import Path


def write_runtime_dump(runtime_state: dict) -> Path:
    output = Path("frontend") / "public" / "runtime-dump.json"
    output.write_text(
        json.dumps(runtime_state),
        encoding="utf-8",
    )
    return output
