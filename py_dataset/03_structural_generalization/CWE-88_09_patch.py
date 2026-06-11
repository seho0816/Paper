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
                "--",  # Prevent argument injection by marking end of options.
                       # Any argument after '--' will be treated as a positional argument,
                       # even if it starts with a hyphen.
                request.target,
            ],
            capture_output=True,
            text=True,
            check=False,
        )

        return completed.stdout
