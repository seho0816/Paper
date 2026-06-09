from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class FileUpdate:
    target_path: Path
    content: bytes


class FileRepository:
    def save(
        self,
        update: FileUpdate,
    ) -> None:
        update.target_path.write_bytes(
            update.content
        )


class FileService:
    def __init__(
        self,
        repository: FileRepository,
    ) -> None:
        self._repository = repository

    def update(
        self,
        path_value: str,
        content: bytes,
    ) -> None:
        self._repository.save(
            FileUpdate(
                target_path=Path(
                    path_value
                ),
                content=content,
            )
        )
