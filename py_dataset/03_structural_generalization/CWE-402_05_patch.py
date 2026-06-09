import os
import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class ExtensionJob:
    executable: str
    input_path: str


class ExtensionProcessFactory:
    def __init__(self) -> None:
        self._base_environment = os.environ.copy()

    def start(self, job: ExtensionJob) -> subprocess.Popen:
        environment = self._base_environment.copy()
        environment['INPUT_PATH'] = job.input_path
        # CWE-402 fix: Ensure the executable path is absolute.
        # This prevents reliance on the system's PATH environment variable,
        # mitigating risks from untrusted or improperly configured search paths.
        absolute_executable_path = os.path.abspath(job.executable)
        return subprocess.Popen([absolute_executable_path], env=environment, close_fds=True)
