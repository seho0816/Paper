import hashlib
from dataclasses import dataclass


@dataclass(frozen=True)
class ArchiveContents:
    payload: bytes
    manifest: dict


class ArchiveIntegrityService:
    def verify(
        self,
        contents: ArchiveContents,
    ) -> bool:
        actual = hashlib.sha256(
            contents.payload
        ).hexdigest()

        return (
            actual
            == contents.manifest[
                "sha256"
            ]
        )
