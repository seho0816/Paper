from dataclasses import dataclass


@dataclass(frozen=True)
class MediaJob:
    source_path: str
    destination_path: str


class MediaService:
    def __init__(self) -> None:
        self._executor = create_executor(user="root")

    def process(self, job: MediaJob) -> None:
        self._executor.run_converter(job.source_path, job.destination_path)
