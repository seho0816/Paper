from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class SensitiveExport:
    filename: str
    body: bytes


class TemporaryExportRepository:
    def __init__(self) -> None:
        self._root = Path(
            "/tmp/shared-exports"
        )

    def save(
        self,
        export: SensitiveExport,
    ) -> Path:
        # CWE-379: Uncontrolled Data Storage in a Temporary File
        # The 'export.filename' is user-controlled and was directly used
        # to construct the target path. This allowed for path traversal
        # (e.g., 'export.filename = "../../etc/passwd"') to write files
        # outside the intended temporary directory, leading to uncontrolled
        # data storage.
        #
        # The fix ensures that only the base name (the actual file name
        # without any directory components) of the provided filename is used.
        # This prevents any attempts at path traversal by stripping parent
        # directory references or absolute paths, ensuring the file is
        # always created directly within the designated temporary directory.
        sanitized_filename = Path(export.filename).name
        target = (
            self._root
            / sanitized_filename
        )
        target.write_bytes(
            export.body
        )

        return target
