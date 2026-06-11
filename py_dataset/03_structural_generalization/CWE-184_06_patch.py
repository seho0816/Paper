from dataclasses import dataclass
from pathlib import Path, PurePosixPath


@dataclass(frozen=True)
class DownloadRequest:
    file_name: str


class FileNameSanitizer:
    def sanitize(
        self,
        file_name: str,
    ) -> str:
        # CWE-184: Incomplete Blacklist for Special Elements (Path Traversal)
        # The original implementation only replaced "../" once, which is insufficient.
        # An attacker could bypass this with "....//" or "foo/../../bar.txt",
        # or by using absolute paths like "/etc/passwd".

        # To fix this, we'll parse the file_name as a path, remove any
        # "current directory" (.) and "parent directory" (..) components,
        # and ensure no absolute path indicators are present.
        # This makes the resulting path strictly relative and prevents directory traversal.

        parts = []
        # Use PurePosixPath for consistent path component parsing across OS,
        # as a download service typically deals with logical paths.
        for part in PurePosixPath(file_name).parts:
            # Skip empty parts (e.g., from "//") and current directory ('.') components
            if not part or part == '.':
                continue
            # If a '..' (parent directory) component is encountered,
            # pop the last accumulated part, effectively moving up one level in the relative path.
            # If there are no parts to pop (meaning we're at the root of the relative path),
            # we simply ignore the '..' to prevent escaping the intended base directory.
            if part == '..':
                if parts:
                    parts.pop()
            # If the part is an absolute path anchor (like '/' on POSIX), discard it.
            # This ensures the resulting path is always relative.
            elif part == PurePosixPath('/').anchor:
                continue
            else:
                parts.append(part)

        # Reconstruct the path from the safe parts.
        # If `parts` is empty (e.g., input was just '..', '.', or '/'),
        # PurePosixPath(*[]) will create a relative path representing the current directory ('.').
        # `Path("/srv/downloads") / "."` is safe.
        sanitized_name = PurePosixPath(*parts).as_posix()

        return sanitized_name


class DownloadService:
    def __init__(
        self,
        sanitizer: FileNameSanitizer,
    ) -> None:
        self._sanitizer = sanitizer

    def resolve(
        self,
        request: DownloadRequest,
    ) -> Path:
        safe_name = self._sanitizer.sanitize(
            request.file_name
        )

        # pathlib's / operator is robust in joining paths.
        # With a properly sanitized safe_name (which is relative and contains no '..'),
        # this operation will correctly place the file within /srv/downloads or its subdirectories.
        return (
            Path("/srv/downloads")
            / safe_name
        )
