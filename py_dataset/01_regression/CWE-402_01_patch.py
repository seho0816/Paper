import os
import subprocess


def convert_document(source_path: str, output_path: str) -> None:
    # CWE-402 fix: Avoid transmitting potentially sensitive parent process environment
    # variables to the child process. Only provide an empty environment or
    # explicitly whitelist necessary variables.
    # For this generic converter, we assume no specific environment variables are
    # required from the parent process. If required, they should be explicitly defined
    # (e.g., {'PATH': os.environ.get('PATH')}).
    child_environment = {}
    subprocess.run(
        ['/opt/tools/converter', source_path, output_path],
        env=child_environment,
        check=True,
    )
