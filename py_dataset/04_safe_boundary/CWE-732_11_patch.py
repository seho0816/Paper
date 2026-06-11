import os
from pathlib import Path

def write_secret_config(path: Path, body: str) -> None:
    path.write_text(body, encoding='utf-8')
    os.chmod(path, 0o600)

