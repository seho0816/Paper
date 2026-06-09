from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class FileUpdate:
    target_path: Path
    content: bytes


class FileRepository:
    def save(
        self,
        update: FileUpdate,
    ) -> None:
        update.target_path.write_bytes(
            update.content
        )


class FileService:
    def __init__(
        self,
        repository: FileRepository,
    ) -> None:
        self._repository = repository

    def update(
        self,
        path_value: str,
        content: bytes,
    ) -> None:
        # Define a safe base directory for file operations.
        # This directory must exist or be explicitly created by the application
        # for files to be stored within it. If it doesn't exist, `resolve()` will raise
        # FileNotFoundError, which is consistent with the original code's behavior
        # if target parent directories didn't exist.
        # Using a subdirectory like 'data' in the current working directory
        # is a common and reasonably safe default for application-specific files.
        safe_base_path = Path("./data").resolve()

        # CWE-59 Mitigation: Validate the user-provided path_value before joining and resolving.
        # 1. Prevent absolute paths from bypassing the base directory.
        # 2. Prevent explicit directory traversal components ('..').
        user_input_path = Path(path_value)
        if user_input_path.is_absolute():
            raise ValueError(f"Absolute paths are not allowed: '{path_value}'")
        if '..' in user_input_path.parts:
            raise ValueError(f"Directory traversal ('..') is not allowed: '{path_value}'")

        # Construct the full path by joining the safe base path with the validated user-provided path.
        # This ensures the user's path is always relative to the safe_base_path.
        potential_target_path = safe_base_path / user_input_path

        # Canonicalize the potential_target_path.
        # `resolve(strict=False)` is used to resolve as much of the path as possible,
        # without raising an error if the final file/directory component does not exist.
        # This is crucial for file creation/writing operations. It resolves symbolic links
        # and '..' components that might have been part of intermediate directories (though '..'
        # in direct input is already prevented above).
        resolved_target_path = potential_target_path.resolve(strict=False)

        # CWE-59 Mitigation: Final check to ensure the resolved path is still contained
        # within the safe base directory, especially after resolving any symbolic links
        # or complex path components that might exist in parent directories.
        # `is_relative_to` (Python 3.9+) checks if this path is a subpath of another path.
        if not resolved_target_path.is_relative_to(safe_base_path):
            raise ValueError(f"Attempted path '{path_value}' resolves outside the allowed directory.")

        # If the path is validated as safe, proceed with the operation, using the resolved path.
        self._repository.save(
            FileUpdate(
                target_path=resolved_target_path,
                content=content,
            )
        )
