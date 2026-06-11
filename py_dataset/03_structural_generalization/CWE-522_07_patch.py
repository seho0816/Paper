from dataclasses import dataclass
from pathlib import Path
import os
from cryptography.fernet import Fernet

@dataclass(frozen=True)
class DesktopSession:
    user_id: str
    token: str


class DesktopSessionStore:
    def __init__(self) -> None:
        self._root = Path.home() / ".desktop-client"
        
        encryption_key_env = os.environ.get("DESKTOP_CLIENT_SECRET_KEY")
        if not encryption_key_env:
            raise ValueError("Encryption key 'DESKTOP_CLIENT_SECRET_KEY' not set in environment.")
        
        try:
            self._fernet = Fernet(encryption_key_env)
        except ValueError as e:
            raise ValueError(f"Invalid encryption key provided for Fernet: {e}")

    def save(self, session: DesktopSession) -> None:
        self._root.mkdir(parents=True, exist_ok=True)
        
        encrypted_token_bytes = self._fernet.encrypt(session.token.encode('utf-8'))
        encrypted_token_str = encrypted_token_bytes.decode('utf-8')

        (self._root / "session.txt").write_text(
            session.user_id + "\n" + encrypted_token_str,
            encoding="utf-8",
        )
