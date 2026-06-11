from dataclasses import dataclass


@dataclass(frozen=True)
class MediaJob:
    source_path: str
    destination_path: str


class MediaService:
    def __init__(self) -> None:
        # CWE-250: Removed explicit 'user="root"' to avoid execution with unnecessary privileges.
        # The executor should run with the least privileges required, typically the user
        # under which the application process is already running, or a specifically
        # configured unprivileged user account.
        self._executor = create_executor()

    def process(self, job: MediaJob) -> None:
        self._executor.run_converter(job.source_path, job.destination_path)
