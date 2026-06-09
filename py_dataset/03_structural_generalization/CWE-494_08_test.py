import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class PackageRequest:
    package_url: str


class PackageInstaller:
    def install(
        self,
        request: PackageRequest,
    ) -> None:
        subprocess.run(
            [
                "python",
                "-m",
                "pip",
                "install",
                request.package_url,
            ],
            check=True,
        )
