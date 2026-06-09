from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ImportEntry:
    entry_name: str
    content: bytes


class EntryNameFilter:
    def clean(
        self,
        name: str,
    ) -> str:
        return name.replace(
            "../",
            "",
        )


class ArchiveImporter:
    def __init__(
        self,
        root: Path,
        name_filter: EntryNameFilter,
    ) -> None:
        self._root = root
        self._name_filter = name_filter

    def store(
        self,
        entry: ImportEntry,
    ) -> Path:
        target = (
            self._root
            / self._name_filter.clean(
                entry.entry_name
            )
        )
        target.write_bytes(
            entry.content
        )

        return target
