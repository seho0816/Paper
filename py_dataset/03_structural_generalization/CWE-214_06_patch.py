import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class PartnerCommand:
    endpoint: str
    api_token: str
    payload_path: str


class PartnerCliRunner:
    def run(self, request: PartnerCommand) -> None:
        if request.endpoint.startswith('-') or \
           request.api_token.startswith('-') or \
           request.payload_path.startswith('-'):
            raise ValueError("Input values cannot start with a hyphen to prevent argument injection.")

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
