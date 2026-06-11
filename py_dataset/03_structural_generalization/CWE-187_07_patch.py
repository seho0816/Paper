import hashlib
from dataclasses import dataclass


def calculate_sha256(data: bytes) -> str:
    """Calculates the SHA256 digest of the given bytes data and returns it as a hexadecimal string."""
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class Package:
    body: bytes
    digest: str


class PackageVerifier:
    def verify(
        self,
        package: Package,
    ) -> bool:
        actual = calculate_sha256(
            package.body
        )

        return (
            actual
            == package.digest
        )
