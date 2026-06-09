import os
import subprocess

from celery import shared_task


@shared_task
def convert_private_document(
    input_path: str,
) -> None:
    secret = open(
        "/run/secrets/converter-key",
        "rb",
    )
    # CWE-403 fix: Removed the explicit instruction to make the file descriptor inheritable.
    # By default, file descriptors opened with open() are usually marked as CLOEXEC on modern Unix systems,
    # meaning they are not inherited by child processes unless explicitly made inheritable.
    # The `close_fds=True` in subprocess.run further ensures this.

    subprocess.run(
        [
            "/opt/tools/converter",
            input_path,
        ],
        # CWE-403 fix: Changed close_fds to True.
        # This ensures that all file descriptors (except standard ones like stdin, stdout, stderr)
        # are closed in the child process's environment before it is executed.
        # This prevents the 'secret' file descriptor from being exposed to the converter process.
        close_fds=True,
        check=True,
    )
    # The original code does not explicitly close the 'secret' file object.
    # While it's generally good practice to close files promptly (e.g., using 'with open(...)'),
    # adding 'secret.close()' would be a functional addition beyond strictly fixing CWE-403,
    # and would alter the code structure, violating the strict rules.
    # The file descriptor's inheritance to the child process is prevented by the fix above.
    # The 'secret' file object will eventually be closed when it's garbage collected
    # after the function call completes.
