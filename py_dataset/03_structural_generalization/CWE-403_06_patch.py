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

        # CWE-403 fix: Set close_fds to True to prevent the child process
        # from inheriting the sensitive file descriptor.
        # This closes all file descriptors except 0, 1, and 2 before
        # the child process is executed.
        subprocess.run(
            [
                request.executable,
                *request.arguments,
            ],
            close_fds=True,
            check=True,
        )
