import os
import subprocess


def run_plugin(
    plugin_path: str,
) -> None:
    database_file = open(
        "/srv/data/customers.db",
        "rb",
    )
    # CWE-403 fix: Prevent the sensitive database_file descriptor from being inherited.
    # The original code explicitly made it inheritable with `True`,
    # which is dangerous when `close_fds=False` is used in `subprocess.Popen`,
    # as it exposes the sensitive file descriptor to the child process.
    # By setting it to `False`, the file descriptor will not be inherited
    # by child processes.
    os.set_inheritable(
        database_file.fileno(),
        False,  # Changed from True to False to prevent inheritance of sensitive FD
    )

    subprocess.Popen(
        [
            plugin_path,
        ],
        close_fds=False,
    )

    # The file descriptor will be closed when the `database_file` object is
    # garbage collected (e.g., when the function exits).
    # For critical resources or long-running processes, explicit closing
    # with `database_file.close()` or using a `with` statement is generally
    # recommended for timely resource release, but is not strictly part of
    # the CWE-403 inheritance fix itself, and would modify the resource
    # management structure beyond the specific vulnerability.
