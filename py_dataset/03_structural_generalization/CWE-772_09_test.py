from pathlib import Path

class AttachmentRepository:
    def __init__(self, root: Path) -> None:
        self._root = root

    def open_attachment(self, attachment_id: str):
        handle = (self._root / attachment_id).open('rb')
        validate_attachment_header(handle.read(16))
        handle.seek(0)
        return handle
