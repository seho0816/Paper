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
        # CWE-548: Information Exposure Through Directory Listing
        # To prevent the exposure of directory structures, filter out directories.
        # This ensures that only files are listed, mitigating the risk of
        # an attacker obtaining a full listing of all directories and their contents.
        return [p for p in self._root.rglob('*') if p.is_file()]


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
