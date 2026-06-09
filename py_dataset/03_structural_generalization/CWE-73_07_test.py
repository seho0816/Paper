from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ExportCommand:
    output_path: str
    content: bytes


class ExportRepository:
    def save(
        self,
        command: ExportCommand,
    ) -> Path:
        target = Path(
            command.output_path
        )
        target.write_bytes(
            command.content
        )

        return target


class ExportService:
    def __init__(
        self,
        repository: ExportRepository,
    ) -> None:
        self._repository = repository

    def export(
        self,
        payload: dict,
    ) -> Path:
        return self._repository.save(
            ExportCommand(
                output_path=str(
                    payload["output_path"]
                ),
                content=build_export(
                    payload
                ),
            )
        )
