import os
from pathlib import Path

def write_export(path: Path, content: str) -> Path:
    path.write_text(content, encoding='utf-8')
    os.chmod(path, 0o644)
    return path
