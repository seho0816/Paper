import json
from pathlib import Path


def write_runtime_dump(runtime_state: dict) -> Path:
    # CWE-552 fix: The original code writes to 'frontend/public/', which is typically
    # a publicly accessible web directory. To prevent sensitive runtime state from
    # being exposed, the file should be written to a non-public location.
    # By removing the 'public' component from the path, the file is placed
    # in the 'frontend' directory itself, which is generally not served directly
    # by a web server, making it inaccessible to external parties.
    output = Path("frontend") / "runtime-dump.json"
    output.write_text(
        json.dumps(runtime_state),
        encoding="utf-8",
    )
    return output
