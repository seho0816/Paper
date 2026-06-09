from pathlib import Path


class UploadStorage:
    def __init__(self, root: Path) -> None:
        self.root = root

    def store(self, original_name: str, body: bytes) -> Path:
        target = self.root / original_name
        target.write_bytes(body)
        return target


def save_profile_attachment(filename: str, content: bytes) -> str:
    storage = UploadStorage(Path("/var/app/uploads"))
    return str(storage.store(filename, content))
