import os
from pathlib import Path

def store_api_key(path: Path, key: str) -> None:
    path.write_text(key, encoding='utf-8')
    os.chmod(path, 0o644)
