import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class CredentialFile:
    filename: str
    body: bytes


class CredentialFileRepository:
    def __init__(
        self,
        root: Path,
    ) -> None:
        self._root = root

    def save(
        self,
        credential: CredentialFile,
    ) -> Path:
        os.umask(
            0o002
        )
        target = (
            self._root
            / credential.filename
        )
        target.write_bytes(
            credential.body
        )

        return target
