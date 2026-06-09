import json
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class CredentialRecord:
    account_id: str
    access_token: str
    refresh_token: str


class FileCredentialRepository:
    def __init__(self, path: Path) -> None:
        self._path = path

    def save(self, record: CredentialRecord) -> None:
        self._path.write_text(
            json.dumps(asdict(record)),
            encoding="utf-8",
        )
