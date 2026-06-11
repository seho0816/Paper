import os
import errno


def read_authorized_file(
    path: str,
) -> bytes:
    fd = -1  # Initialize file descriptor to an invalid value
    try:
        # Open the file using os.open with O_NOFOLLOW to prevent symbolic link attacks (CWE-367).
        # O_NOFOLLOW ensures that if 'path' is a symbolic link, the call will fail,
        # preventing access to an unintended file. This is crucial for fixing 'Improper Link Resolution'.
        # This also implicitly checks read permissions; if the process cannot read the file,
        # os.open will raise an OSError (typically EACCES).
        # The prior os.access check is removed as it creates a 'Time-of-check Time-of-use' (TOCTOU)
        # race condition with the subsequent open() call, which is the core of CWE-367.
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)

        # Use os.fdopen to get a file object from the file descriptor.
        # The 'with' statement ensures the file object (and thus the fd) is properly closed
        # when exiting the block, whether by normal completion or an exception.
        with os.fdopen(fd, "rb") as source:
            return source.read()
    except OSError as e:
        # Catch various OSError types that can occur during os.open and map them
        # to PermissionError to maintain the original function's error signature for access issues.
        # errno.EACCES: Permission denied (e.g., file not readable, or directory not searchable)
        # errno.ENOENT: No such file or directory (file doesn't exist)
        # errno.ELOOP: Too many levels of symbolic links (encountered a symlink with O_NOFOLLOW)
        #              This specific error is the primary fix for CWE-367 using O_NOFOLLOW.
        if e.errno in (errno.EACCES, errno.ENOENT, errno.ELOOP):
            raise PermissionError(path) from e
        else:
            # Re-raise any other unexpected OS errors.
            raise
    # No finally block is needed to call os.close(fd) because:
    # 1. If os.open fails, fd remains -1.
    # 2. If os.open succeeds, os.fdopen takes ownership of the fd, and the 'with' statement
    #    around os.fdopen ensures the fd is closed when the block is exited.
