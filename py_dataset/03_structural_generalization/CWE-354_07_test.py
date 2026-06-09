import hashlib
from dataclasses import dataclass


@dataclass(frozen=True)
class Package:
    body: bytes
    declared_sha256: str


class PackageVerifier:
    def verify(
        self,
        package: Package,
    ) -> bool:
        actual = hashlib.sha256(
            package.body
        ).hexdigest()

        return (
            actual
            == package.declared_sha256
        )
