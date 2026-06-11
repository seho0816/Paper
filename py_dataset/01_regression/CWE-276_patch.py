import os
from pathlib import Path


def write_service_token(
    token: str,
) -> Path:
    original_umask = os.umask(0o077)  # CWE-276 fix: Set a restrictive umask (e.g., 0o077 for 0o600 permissions)
    try:
        path = Path(
            "service_token.txt"
        )
        path.write_text(
            token,
            encoding="utf-8",
        )
    finally:
        os.umask(original_umask)  # Restore the original umask

    return path
