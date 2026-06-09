import hashlib
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class UpdatePackage:
    path: Path
    expected_digest: str


class UpdateVerifier:
    def verify(
        self,
        package: UpdatePackage,
    ) -> bool:
        digest = hashlib.sha256(
            package.path.read_bytes()
        ).hexdigest()

        return (
            digest
            == package.expected_digest
        )
