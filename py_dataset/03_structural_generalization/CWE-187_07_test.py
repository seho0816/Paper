from dataclasses import dataclass


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
            actual[:8]
            == package.digest[:8]
        )
