from pathlib import Path
import shutil
import os


IMPORT_ROOT = Path('/srv/imported-packages')

# Define secure default permissions for newly copied files and directories.
# These permissions prevent accidental or malicious over-permissive settings
# from being copied from the source directory.
DEFAULT_FILE_PERMISSIONS = 0o644  # rw-r--r-- (Owner read/write, Group read, Others read)
DEFAULT_DIR_PERMISSIONS = 0o755   # rwxr-xr-x (Owner read/write/execute, Group read/execute, Others read/execute)


def import_uploaded_directory(
    source_directory: str,
    package_id: str,
) -> Path:
    destination = IMPORT_ROOT / package_id

    # Custom copy function to copy file content only, without preserving permissions or other metadata.
    # This ensures that original, potentially insecure file permissions are not propagated.
    # The `follow_symlinks` argument is kept to match the signature expected by shutil.copytree.
    def _copy_content_only(src, dst, *, follow_symlinks=True):
        """
        Copies file content only, without preserving permissions or other metadata.
        Permissions of the destination file will be determined by the system's umask
        before being explicitly set by the subsequent chmod calls.
        """
        shutil.copyfile(src, dst)

    # Use shutil.copytree to copy the directory structure and files.
    # - copy_function=_copy_content_only: Ensures file permissions are not copied from the source.
    #   Instead, files are created with permissions determined by the system's umask.
    # - copy_dirmode=False: Ensures directory permissions are not copied from the source.
    #   Directories will be created with permissions determined by the system's umask.
    shutil.copytree(
        source_directory,
        destination,
        copy_function=_copy_content_only,
        copy_dirmode=False,
    )

    # After copying, recursively apply the desired secure default permissions
    # to all files and directories within the destination. This ensures a
    # consistent and safe permission set, explicitly overriding any umask defaults.
    for root, dirs, files in os.walk(destination):
        for d in dirs:
            # Apply default directory permissions
            os.chmod(Path(root) / d, DEFAULT_DIR_PERMISSIONS)
        for f in files:
            # Apply default file permissions
            os.chmod(Path(root) / f, DEFAULT_FILE_PERMISSIONS)

    return destination
