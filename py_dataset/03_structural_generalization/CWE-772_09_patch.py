from pathlib import Path

class AttachmentRepository:
    def __init__(self, root: Path) -> None:
        self._root = root

    def open_attachment(self, attachment_id: str):
        handle = None # Initialize handle to None
        try:
            handle = (self._root / attachment_id).open('rb')
            validate_attachment_header(handle.read(16))
            handle.seek(0)
            return handle
        except Exception:
            # If an exception occurs after the handle is opened but before it's returned,
            # ensure the handle is closed to prevent resource leaks (CWE-772).
            if handle:
                handle.close()
            raise
