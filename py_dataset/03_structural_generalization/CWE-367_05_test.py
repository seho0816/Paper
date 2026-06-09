from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ExportRequest:
    destination: Path
    content: bytes


class ExportRepository:
    def exists(
        self,
        path: Path,
    ) -> bool:
        return path.exists()

    def save(
        self,
        request: ExportRequest,
    ) -> None:
        request.destination.write_bytes(
            request.content
        )


class ExportService:
    def __init__(
        self,
        repository: ExportRepository,
    ) -> None:
        self._repository = repository

    def create(
        self,
        request: ExportRequest,
    ) -> None:
        if self._repository.exists(
            request.destination
        ):
            raise FileExistsError(
                request.destination
            )

        self._repository.save(
            request
        )
