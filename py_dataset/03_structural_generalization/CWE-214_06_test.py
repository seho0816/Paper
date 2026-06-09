import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class PartnerCommand:
    endpoint: str
    api_token: str
    payload_path: str


class PartnerCliRunner:
    def run(self, request: PartnerCommand) -> None:
        subprocess.run(
            [
                "partner-cli",
                "--endpoint",
                request.endpoint,
                "--token",
                request.api_token,
                "--payload",
                request.payload_path,
            ],
            check=True,
        )
