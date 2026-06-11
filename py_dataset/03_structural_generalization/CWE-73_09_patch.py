import os
from dataclasses import dataclass
from pathlib import Path


# Define a secure base directory for file uploads.
# This path should be configured externally, e.g., via environment variable.
# It is resolved to ensure it is an absolute and canonical path,
# which is crucial for subsequent security checks.
# Raises KeyError if UPLOAD_BASE_DIR is not set in environment.
_UPLOAD_BASE_DIR = Path(os.environ["UPLOAD_BASE_DIR"]).resolve()


@dataclass(frozen=True)
class MediaRender:
    client_output_path: str
    payload: bytes


class MediaRenderService:
    def persist(
        self,
        render: MediaRender,
    ) -> str:
        # Construct the full intended path by combining the secure base directory
        # with the client-provided relative path.
        # pathlib automatically handles path separators and ensures proper joining.
        target_path = _UPLOAD_BASE_DIR / render.client_output_path

        # Resolve the target path to get its canonical, absolute form.
        # This resolves '..', '.', and symbolic links, providing the actual path
        # on the filesystem that would be accessed.
        resolved_path = target_path.resolve()

        # SECURITY CHECK: Prevent directory traversal (CWE-73).
        # Verify that the resolved_path is still located within the _UPLOAD_BASE_DIR.
        # If an attacker uses path traversal sequences (e.g., "../../") to
        # escape the base directory, this check will detect it because
        # the resolved_path will not be relative to _UPLOAD_BASE_DIR.
        if not resolved_path.is_relative_to(_UPLOAD_BASE_DIR):
            raise ValueError("Attempted path traversal detected!")

        # Ensure the parent directories for the resolved_path exist.
        # `parents=True` creates any necessary intermediate directories.
        # `exist_ok=True` prevents an error if the directory already exists.
        # This step is safe as `resolved_path` has already been validated.
        resolved_path.parent.mkdir(parents=True, exist_ok=True)

        # Write the payload to the safely validated and resolved path.
        resolved_path.write_bytes(
            render.payload
        )

        return str(resolved_path)
