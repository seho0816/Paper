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
        return subprocess.Popen([job.executable], env=environment, close_fds=True)
