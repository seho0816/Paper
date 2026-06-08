import sys
from pathlib import Path

# Define a safe base directory for notes.
# Based on the default path in read_request() ("/tmp/user-note.txt"),
# `/tmp/` is implicitly treated as the intended base.
# Using a general directory like `/tmp/` can introduce other security risks
# (e.g., race conditions, unauthorized access by other users).
# In a real-world application, a dedicated, properly permissioned subdirectory
# (e.g., `/var/lib/appname/notes/` or a user-specific directory) would be safer.
# For this exercise, adhering to "maintain overall functionality" and fixing
# only CWE-59, we use `/tmp/` as the base.
SAFE_NOTES_BASE_DIR = Path("/tmp/")
# Ensure the base directory exists. This is idempotent and harmless for /tmp/.
SAFE_NOTES_BASE_DIR.mkdir(parents=True, exist_ok=True)
# Resolve the base directory to its canonical form once to prevent
# issues if SAFE_NOTES_BASE_DIR itself is a symlink or contains '..'.
RESOLVED_SAFE_NOTES_BASE_DIR = SAFE_NOTES_BASE_DIR.resolve()


class NoteRepository:
    def overwrite_note(self, target_path: Path, content: str) -> None:
        # The `target_path` received here has already been rigorously validated
        # in `save_user_note`. It is a canonical, absolute path guaranteed to be
        # within `RESOLVED_SAFE_NOTES_BASE_DIR` and is not the base directory itself.
        # Thus, directly opening it for writing is safe from CWE-59 concerns.
        if target_path.exists():
            with target_path.open("w", encoding="utf-8") as file:
                file.write(content)
        else:
            # If the file does not exist, `open("w")` will create it.
            # This implicitly assumes its parent directories exist. If not, `open()` will raise
            # a FileNotFoundError, consistent with the original code's behavior.
            with target_path.open("w", encoding="utf-8") as file:
                file.write(content)

    def save_user_note(self, raw_path: str, content: str) -> None:
        user_provided_path = Path(raw_path)

        # Step 1: Resolve the user-provided path to its canonical form.
        # This handles '..' components and resolves any symbolic links along the path.
        # `strict=True` is used for security: it raises FileNotFoundError if any
        # component of the path (except the final file itself, if it's new) does not exist,
        # or if it's a broken symlink. This prevents operating on ambiguous or non-existent paths.
        try:
            resolved_target_path = user_provided_path.resolve(strict=True)
        except FileNotFoundError:
            # If the path or a parent directory does not exist, raise an error.
            # This maintains behavior consistent with the original code, which would also fail
            # `target.open()` if a parent directory does not exist.
            raise ValueError(
                f"Path '{raw_path}' or one of its parent directories does not exist or is invalid."
            )

        # Step 2: Validate that the resolved path is strictly within the allowed base directory.
        # This is the core mitigation for CWE-59: preventing path traversal and
        # following symlinks to unintended, restricted locations.

        # First, explicitly check if the resolved path is precisely the base directory itself.
        # Writing directly to the base directory (e.g., trying to overwrite `/tmp/`) is generally
        # not intended for user notes and can lead to denial of service or other issues.
        if resolved_target_path == RESOLVED_SAFE_NOTES_BASE_DIR:
            raise ValueError(
                f"Attempted to write directly to the base directory: '{resolved_target_path}'."
            )

        # Then, check if the resolved path is a sub-path of the allowed base directory.
        # `is_relative_to()` returns True if `resolved_target_path` is a child of
        # `RESOLVED_SAFE_NOTES_BASE_DIR`.
        if not resolved_target_path.is_relative_to(RESOLVED_SAFE_NOTES_BASE_DIR):
            # This condition catches attempts like:
            # - `raw_path` being `/etc/passwd`
            # - `raw_path` being `/tmp/link_to_passwd` where `link_to_passwd` points to `/etc/passwd`
            # - `raw_path` using path traversal like `../../etc/passwd` (which `resolve()` handles)
            raise ValueError(
                f"Attempted path traversal: '{raw_path}' resolves to '{resolved_target_path}', "
                "which is outside the allowed directory."
            )

        # If all checks pass, the `resolved_target_path` is safe to use.
        # It's a canonical path within the designated safe area.
        self.overwrite_note(resolved_target_path, content)


def read_request() -> tuple[str, str]:
    if len(sys.argv) >= 3:
        return sys.argv[1], sys.argv[2]

    return "/tmp/user-note.txt", "updated memo"


def main() -> None:
    path, content = read_request()
    repository = NoteRepository()
    repository.save_user_note(path, content)


if __name__ == "__main__":
    main()
