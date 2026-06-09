import subprocess
from dataclasses import dataclass
import shutil
import os


@dataclass(frozen=True)
class ConversionRequest:
    source: str
    destination: str


class MediaToolRunner:
    def __init__(self) -> None:
        # CWE-426: Untrusted Search Path mitigation.
        # Resolve the full, absolute path to the executable during initialization.
        # This prevents the operating system from searching the PATH environment
        # variable for the executable name every time it's invoked,
        # thereby mitigating the risk of executing a malicious program
        # placed earlier in the search path.
        ffmpeg_path = shutil.which("ffmpeg")
        if ffmpeg_path is None:
            raise FileNotFoundError(
                "ffmpeg executable not found in system PATH. "
                "Please ensure ffmpeg is installed and accessible."
            )
        self._executable = ffmpeg_path

    def convert(
        self,
        request: ConversionRequest,
    ) -> None:
        subprocess.run(
            [
                self._executable,  # Now uses the absolute path to ffmpeg
                "-i",
                request.source,
                request.destination,
            ],
            check=True,
        )
