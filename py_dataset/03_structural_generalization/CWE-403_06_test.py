import os
import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class ProcessRequest:
    executable: str
    arguments: list[str]


class ProcessRunner:
    def run(
        self,
        request: ProcessRequest,
    ) -> None:
        secret_file = open(
            "/run/secrets/application-key",
            "rb",
        )
        os.set_inheritable(
            secret_file.fileno(),
            True,
        )

        subprocess.run(
            [
                request.executable,
                *request.arguments,
            ],
            close_fds=False,
            check=True,
        )
