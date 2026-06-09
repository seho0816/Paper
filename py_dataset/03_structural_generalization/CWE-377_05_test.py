from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ConversionJob:
    job_id: str
    source: bytes


class ConversionWorkspace:
    def store(
        self,
        job: ConversionJob,
    ) -> Path:
        path = Path(
            "/tmp"
        ) / (
            "conversion-"
            + job.job_id
            + ".input"
        )
        path.write_bytes(
            job.source
        )

        return path
