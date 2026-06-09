import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class DiagnosticCommand:
    executable: str
    target: str


class DiagnosticRunner:
    def execute(
        self,
        command: DiagnosticCommand,
    ) -> str:
        completed = subprocess.run(
            [
                command.executable,
                command.target,
            ],
            capture_output=True,
            text=True,
            check=False,
        )

        return completed.stdout


class DiagnosticService:
    def __init__(
        self,
        runner: DiagnosticRunner,
    ) -> None:
        self._runner = runner

    def run(
        self,
        payload: dict,
    ) -> str:
        command = DiagnosticCommand(
            executable=str(
                payload["tool"],
            ),
            target=str(
                payload["target"],
            ),
        )

        return self._runner.execute(
            command,
        )
