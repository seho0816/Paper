from dataclasses import dataclass
from pathlib import Path
import os


@dataclass(frozen=True)
class ExportCommand:
    output_path: str
    content: bytes


class ExportRepository:
    # Define a base directory where all exports must reside.
    # It can be configured via an environment variable, falling back to a subdirectory in the current working directory.
    _BASE_EXPORT_DIR = Path(os.getenv("EXPORT_ROOT_DIR", Path.cwd() / "exports"))

    def save(
        self,
        command: ExportCommand,
    ) -> Path:
        # Ensure the base export directory exists.
        # This is safe as _BASE_EXPORT_DIR is controlled by the application.
        self._BASE_EXPORT_DIR.mkdir(parents=True, exist_ok=True)

        requested_path_obj = Path(command.output_path)

        # Enforce that user-provided paths must be relative to prevent absolute path manipulation.
        if requested_path_obj.is_absolute():
            raise ValueError("Absolute paths are not allowed. Please provide a relative path for the export.")

        # Construct the full path by joining the base directory with the user-provided relative path.
        potential_target = self._BASE_EXPORT_DIR / requested_path_obj

        # Resolve the path to get its canonical, absolute form, handling '..', '.', and symlinks.
        target = potential_target.resolve()

        # Get the resolved canonical form of the base directory for a robust comparison.
        resolved_base_dir = self._BASE_EXPORT_DIR.resolve()

        # CRITICAL SECURITY CHECK:
        # Verify that the resolved target path is still a sub-path of the resolved base directory.
        # This prevents path traversal attacks where an attacker might use '..' to escape the intended directory.
        if not target.is_relative_to(resolved_base_dir):
            raise ValueError(
                "Attempted path traversal detected. The resolved output path is not within the allowed export directory."
            )

        # Ensure the parent directory of the target file exists before writing.
        # This is safe because 'target' has already been validated against traversal.
        target.parent.mkdir(parents=True, exist_ok=True)

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
