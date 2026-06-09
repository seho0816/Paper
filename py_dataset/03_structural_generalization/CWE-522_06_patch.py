import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from cryptography.fernet import Fernet


@dataclass(frozen=True)
class CredentialRecord:
    account_id: str
    access_token: str
    refresh_token: str


class FileCredentialRepository:
    def __init__(self, path: Path) -> None:
        self._path = path
        # CWE-522 fix: Ensure encryption key is present for protecting credentials.
        try:
            key = os.environ["CREDENTIAL_ENCRYPTION_KEY"].encode('utf-8')
            self._fernet = Fernet(key)
        except KeyError:
            raise ValueError("CREDENTIAL_ENCRYPTION_KEY environment variable not set. Cannot secure credentials.")

    def save(self, record: CredentialRecord) -> None:
        record_dict = asdict(record)
        
        # CWE-522 fix: Encrypt sensitive fields before saving them to disk.
        # Fernet.encrypt returns base64-encoded bytes, which are then decoded to a UTF-8 string
        # for storage within the JSON structure.
        record_dict["access_token"] = self._fernet.encrypt(record_dict["access_token"].encode('utf-8')).decode('utf-8')
        record_dict["refresh_token"] = self._fernet.encrypt(record_dict["refresh_token"].encode('utf-8')).decode('utf-8')
        
        self._path.write_text(
            json.dumps(record_dict),
            encoding="utf-8",
        )
