import zipfile
from pathlib import Path


EXTRACT_ROOT = Path(
    "/tmp/extracted"
)


def extract_uploaded_archive(
    archive_path: Path,
) -> None:
    # Ensure the root extraction directory exists.
    # It's good practice to create it if it doesn't exist before extraction.
    EXTRACT_ROOT.mkdir(parents=True, exist_ok=True)

    # Get the canonical, absolute path of the extraction root.
    # This is crucial for comparison against resolved member paths to prevent Zip Slip.
    canonical_extract_root = EXTRACT_ROOT.resolve()

    with zipfile.ZipFile(archive_path) as archive:
        for member in archive.infolist():
            # Construct the absolute target path for the current member *if* it were extracted.
            # Path(member.filename) handles potential path separators within the member name.
            # .resolve() canonicalizes the path, resolving '..' components and symlinks,
            # which is essential for detecting path traversal attempts.
            target_path_abs = (EXTRACT_ROOT / Path(member.filename)).resolve()

            # --- CWE-409 Zip Slip mitigation ---
            # Check if the resolved target path is attempting to escape the intended extraction root.
            # .is_relative_to() ensures that target_path_abs is a subpath of canonical_extract_root.
            # If target_path_abs is the same as canonical_extract_root (e.g., if member.filename is '..'),
            # .is_relative_to() will return True, but for directories, we need to ensure it's not trying
            # to overwrite the root directory itself. For files within the root, it's fine.
            # This check robustly prevents files from being extracted outside EXTRACT_ROOT.
            if not target_path_abs.is_relative_to(canonical_extract_root):
                # If it's not a subpath, it's a malicious Zip Slip attempt.
                # Skip this member to prevent writing outside EXTRACT_ROOT.
                continue
            # --- End CWE-409 mitigation ---

            # If the member is a directory, create it.
            # .mkdir(parents=True, exist_ok=True) creates intermediate directories and
            # doesn't raise an error if the directory already exists.
            if member.is_dir():
                target_path_abs.mkdir(parents=True, exist_ok=True)
            else:
                # For files, ensure the parent directory exists, then extract the file.
                target_path_abs.parent.mkdir(parents=True, exist_ok=True)
                # Open the member from the archive and write its content to the validated absolute path.
                with archive.open(member) as source, open(target_path_abs, "wb") as target:
                    target.write(source.read())
