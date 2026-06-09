import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class DiagnosticRequest:
    target: str


class DiagnosticRunner:
    def execute(
        self,
        request: DiagnosticRequest,
    ) -> str:
        completed = subprocess.run(
            [
                "ping",
                "-c",
                "1",
                request.target,
            ],
            capture_output=True,
            text=True,
            check=False,
        )

        return completed.stdout
