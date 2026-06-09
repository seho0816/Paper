import os
from pathlib import Path

def install_deployment_script(path: Path, script: str) -> None:
    path.write_text(script, encoding='utf-8')
    os.chmod(path, 0o777)
