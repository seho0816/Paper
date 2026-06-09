import os
import subprocess


def start_worker(
    worker_path: str,
) -> None:
    token_file = open(
        "/run/secrets/worker-token",
        "rb",
    )
    # CWE-403 Fix:
    # The original code used `os.set_inheritable(token_file.fileno(), True)`
    # combined with `close_fds=False` in `subprocess.Popen`. This combination
    # allowed the sensitive `token_file` descriptor (and potentially all other
    # inheritable descriptors) to be inherited by the child process without
    # specific control, exposing sensitive information (CWE-403).
    #
    # To fix this, we remove the broad `os.set_inheritable` call. Instead,
    # we explicitly pass *only* the required file descriptor using `pass_fds`,
    # and ensure all other descriptors are closed by setting `close_fds=True`.
    # The `pass_fds` argument securely handles making the specified descriptor
    # inheritable for the specific subprocess call.
    # Original line removed: os.set_inheritable(token_file.fileno(), True)

    subprocess.Popen(
        [
            worker_path,
        ],
        close_fds=True,  # Ensures all other file descriptors are closed in the child process.
        pass_fds=[token_file.fileno()],  # Explicitly passes only the desired file descriptor.
    )
