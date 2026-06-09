import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class CertificateExport:
    source_path: str
    passphrase: str
    destination_path: str


class CertificateExportService:
    def export(self, request: CertificateExport) -> None:
        subprocess.run(
            [
                "certificate-tool",
                "export",
                "--source",
                request.source_path,
                "--passphrase",
                request.passphrase,
                "--output",
                request.destination_path,
            ],
            check=True,
        )
