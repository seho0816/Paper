import os
from pathlib import Path


UPLOAD_DIR = Path("/var/app/uploads")


def build_user_file_path(filename: str) -> Path:
    return UPLOAD_DIR / filename


def read_uploaded_file(filename: str) -> str:
    user_provided_path = build_user_file_path(filename)

    # Resolve UPLOAD_DIR to its canonical form. This is typically stable for a constant.
    # Doing this once ensures consistent comparison.
    canonical_upload_dir = UPLOAD_DIR.resolve()

    try:
        # Resolve the user-provided path to its canonical, absolute form,
        # strictly requiring it to exist. This step atomically checks for existence,
        # resolves any symbolic links, and normalizes '..' components.
        # This replaces the non-atomic 'os.path.exists()' check and mitigates TOCTOU.
        resolved_path = user_provided_path.resolve(strict=True)
    except FileNotFoundError:
        # If the file does not exist or the path cannot be resolved (e.g., broken symlink),
        # raise FileNotFoundError, consistent with the original behavior.
        raise FileNotFoundError(filename)
    except Exception:
        # Catch any other unexpected errors during path resolution (e.g., permission denied
        # on an intermediate directory) and re-raise as FileNotFoundError for consistency.
        raise FileNotFoundError(filename)

    # Crucially, verify that the resolved path is indeed a subpath of the canonical UPLOAD_DIR.
    # This prevents path traversal attacks, especially via symbolic links that could point
    # outside the intended upload directory, which is a common vector for CWE-367 in file operations.
    if not resolved_path.is_relative_to(canonical_upload_dir):
        # If the resolved path escapes the upload directory, treat it as if the file
        # was not found within the allowed scope.
        raise FileNotFoundError(filename)

    # Now, open the resolved and verified path. At this point, 'resolved_path' is guaranteed
    # to exist and to be within the intended 'UPLOAD_DIR', mitigating the CWE-367 vulnerability.
    with open(resolved_path, "r", encoding="utf-8") as file:
        return file.read()


def get_file_preview(filename: str) -> dict:
    content = read_uploaded_file(filename)

    return {
        "filename": filename,
        "preview": content[:200],
    }


def main() -> None:
    print(get_file_preview("profile.txt"))


if __name__ == "__main__":
    main()
