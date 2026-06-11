import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class PackageRequest:
    package_url: str
    expected_hash: str


class PackageInstaller:
    def install(
        self,
        request: PackageRequest,
    ) -> None:
        if not request.expected_hash:
            raise ValueError("An expected integrity hash is required for package installation.")

        subprocess.run(
            [
                "python",
                "-m",
                "pip",
                "install",
                request.package_url,
                "--hash",
                request.expected_hash,
            ],
            check=True,
        )
