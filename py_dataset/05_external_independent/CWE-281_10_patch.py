from pathlib import Path
import shutil
import os


def resolve_publish_document(
    _root,
    info,
    staged_path: str,
) -> dict:
    source = Path(staged_path)
    target = (
        info.context.document_root
        / source.name
    )

    # CWE-281: Improper Preservation of Permissions
    # shutil.copy2 preserves all file metadata, including potentially overly
    # permissive permissions from the source file. For published documents,
    # it's safer to explicitly set secure, minimal permissions on the target file.
    # This ensures that sensitive permissions from the staging area are not
    # propagated to the public document root.

    # 1. Copy only the content of the file from source to target.
    # This avoids inheriting potentially insecure permissions from the source.
    shutil.copyfile(source, target)

    # 2. Explicitly set secure permissions for the newly copied file.
    # For a general "document" that is published, a common secure permission is
    # 0o644 (rw-r--r--). This allows the owner to read and write, and the group
    # and others to only read, preventing execution or unintended modifications.
    os.chmod(target, 0o644)

    return {
        'path': str(target),
    }
