import os
from pathlib import Path

def install_deployment_script(path: Path, script: str) -> None:
    path.write_text(script, encoding='utf-8')
    # CWE-732 fix: Set restrictive permissions for the critical deployment script.
    # 0o700 grants read, write, and execute permissions only to the file owner.
    os.chmod(path, 0o700)
