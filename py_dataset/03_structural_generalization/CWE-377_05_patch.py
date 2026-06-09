from dataclasses import dataclass
from pathlib import Path
import tempfile
import os

@dataclass(frozen=True)
class ConversionJob:
    job_id: str
    source: bytes

class ConversionWorkspace:
    def store(
        self,
        job: ConversionJob,
    ) -> Path:
        # dir="/tmp" 파라미터 제거로 Bandit 오탐 해결
        fd, temp_filepath_str = tempfile.mkstemp(
            prefix="conversion-",
            suffix=".input"
        )
        path = Path(temp_filepath_str)

        try:
            with os.fdopen(fd, 'wb') as tmp_file:
                tmp_file.write(job.source)
        except Exception:
            path.unlink(missing_ok=True)
            raise

        return path