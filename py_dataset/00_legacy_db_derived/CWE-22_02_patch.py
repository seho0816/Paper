import os
import zipfile
from flask import request

UPLOAD_DIR = "/var/app/uploads"

def extract_zip():
    archive = request.files["archive"]
    archive.save("/tmp/upload.zip")

    # Canonicalize UPLOAD_DIR once for robust comparison.
    # This resolves any '..', '.', or symlinks in UPLOAD_DIR itself.
    abs_upload_dir = os.path.abspath(UPLOAD_DIR)

    with zipfile.ZipFile("/tmp/upload.zip") as zf:
        for member in zf.namelist():
            # Construct the full hypothetical path where the member *would* be extracted.
            # Example: UPLOAD_DIR = "/var/app/uploads", member = "../../etc/passwd"
            # target_file_path becomes "/var/app/uploads/../../etc/passwd"
            target_file_path = os.path.join(UPLOAD_DIR, member)

            # Normalize and resolve the `target_file_path`. This will process `..` components.
            # Example: "/var/app/uploads/../../etc/passwd" becomes "/etc/passwd" after abspath and normpath.
            abs_target_file_path = os.path.normpath(os.path.abspath(target_file_path))

            # Security check: Ensure the resolved absolute target path is within the allowed upload directory.
            # It must start with `abs_upload_dir` followed by `os.sep` (to ensure it's a subdirectory)
            # OR it must be exactly `abs_upload_dir` (e.g., if a directory entry itself points to the root).
            if not (abs_target_file_path == abs_upload_dir or abs_target_file_path.startswith(abs_upload_dir + os.sep)):
                # If the path escapes the UPLOAD_DIR, skip this member to prevent path traversal.
                continue

            # If the path is safe, proceed with extraction.
            # `zf.extract` will handle creating necessary parent directories.
            zf.extract(member, UPLOAD_DIR)

    return "extracted"
