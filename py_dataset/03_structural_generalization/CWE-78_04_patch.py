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
        tool = str(payload["tool"])

        # CWE-78 Fix: Implement a whitelist for allowed executables to prevent OS Command Injection.
        # This prevents an attacker from specifying arbitrary system commands via the 'tool' payload.
        allowed_tools = {"echo", "ls", "ping"} # Example whitelist of safe diagnostic tools
        if tool not in allowed_tools:
            raise ValueError(f"'{tool}' is not an allowed diagnostic tool.")

        command = DiagnosticCommand(
            executable=tool,
            target=str(
                payload["target"],
            ),
        )

        return self._runner.execute(
            command,
        )
