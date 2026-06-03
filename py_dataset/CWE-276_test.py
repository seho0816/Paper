import os
from pathlib import Path


class TokenFileWriter:
    def write_token(self, token: str) -> Path:
        previous_umask = os.umask(0)
        token_path = Path("partner_service_token.txt")
        token_path.write_text(token, encoding="utf-8")
        os.umask(previous_umask)

        return token_path
