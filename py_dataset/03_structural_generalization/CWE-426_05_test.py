import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class ConversionRequest:
    source: str
    destination: str


class MediaToolRunner:
    def __init__(self) -> None:
        self._executable = "ffmpeg"

    def convert(
        self,
        request: ConversionRequest,
    ) -> None:
        subprocess.run(
            [
                self._executable,
                "-i",
                request.source,
                request.destination,
            ],
            check=True,
        )
