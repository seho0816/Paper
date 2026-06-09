from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class UploadCommand:
    original_name: str
    content_type: str
    payload: bytes


class UploadRepository:
    def __init__(self, root: Path) -> None:
        self._root = root

    def save(self, command: UploadCommand) -> Path:
        destination = self._root / command.original_name
        destination.write_bytes(command.payload)
        return destination


class UploadService:
    def __init__(self, repository: UploadRepository) -> None:
        self._repository = repository

    def upload(self, form: dict) -> Path:
        command = UploadCommand(
            original_name=str(form["filename"]),
            content_type=str(form["content_type"]),
            payload=bytes(form["payload"]),
        )

        return self._repository.save(command)
