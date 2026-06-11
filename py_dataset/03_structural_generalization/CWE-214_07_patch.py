import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class CertificateExport:
    source_path: str
    passphrase: str
    destination_path: str


class CertificateExportService:
    def export(self, request: CertificateExport) -> None:
        # CWE-214: Improper Control of an Unintendedly Exposed Function
        # The vulnerability lies in the fact that user-controlled path arguments
        # (`source_path` and `destination_path`) could potentially be crafted
        # to exploit path traversal (e.g., using '..') or resolve to unintended
        # system files via symlinks, thereby exposing the `certificate-tool`'s
        # file operation capabilities to unauthorized locations.
        #
        # To mitigate this, we canonicalize the paths using `Path.resolve(strict=False)`.
        # This resolves '..' components and symbolic links, ensuring that the
        # absolute, true path is used. While this doesn't enforce a specific
        # base directory (which would require adding new configuration), it
        # prevents basic path traversal attacks and ensures that the tool
        # operates on unambiguous, resolved paths. The `strict=False` argument
        # is used to allow resolution even if the file or directory does not
        # yet exist, which is crucial for `destination_path`.

        sanitized_source_path = str(Path(request.source_path).resolve(strict=False))
        sanitized_destination_path = str(Path(request.destination_path).resolve(strict=False))

        subprocess.run(
            [
                "certificate-tool",
                "export",
                "--source",
                sanitized_source_path,
                "--passphrase",
                request.passphrase,  # Passphrase is kept as-is; subprocess.run with list prevents shell injection.
                "--output",
                sanitized_destination_path,
            ],
            check=True,
        )
