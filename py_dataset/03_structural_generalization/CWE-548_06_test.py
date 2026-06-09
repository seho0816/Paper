from pathlib import Path


class FileSystemRepository:
    def __init__(
        self,
        root: Path,
    ) -> None:
        self._root = root

    def list_all(
        self,
    ) -> list[Path]:
        return list(
            self._root.rglob('*')
        )


class DirectoryIndexController:
    def __init__(
        self,
        repository: FileSystemRepository,
    ) -> None:
        self._repository = repository

    def get(
        self,
    ) -> dict:
        return {
            'entries': [
                str(path)
                for path in self._repository.list_all()
            ],
        }
