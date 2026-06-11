import hashlib
import hmac
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

        expected = contents.manifest["sha256"]

        return hmac.compare_digest(
            actual,
            expected
        )
