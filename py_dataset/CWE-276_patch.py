import os
from pathlib import Path


class TokenFileWriter:
    def write_token(self, token: str) -> Path:
        token_path = Path("partner_service_token.txt")
        token_path.write_text(token, encoding="utf-8")
        # CWE-276: Incorrect Default Permissions
        # The os.umask(0) call makes newly created files world-writable.
        # This is fixed by explicitly setting restrictive permissions (e.g., 0o600)
        # on the sensitive file immediately after creation/writing.
        # This ensures only the owner can read and write the token file,
        # regardless of the system's umask setting.
        token_path.chmod(0o600)
        return token_path
