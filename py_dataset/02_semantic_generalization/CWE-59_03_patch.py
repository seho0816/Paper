import os


def protect_file(
    path: str,
) -> None:
    fd = -1
    try:
        # Open the file without following symbolic links (CWE-59 mitigation).
        # os.O_RDONLY is sufficient to get a file descriptor for fchmod.
        # os.O_NOFOLLOW ensures that if 'path' is a symbolic link, os.open will fail
        # rather than operating on the symlink's target, thus preventing link following.
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        os.fchmod(
            fd,
            0o600,
        )
    finally:
        if fd != -1:
            os.close(fd)
