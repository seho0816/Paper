import subprocess

ALLOWED_OPERATIONS = {
    "status": [
        "/usr/bin/systemctl",
        "status",
        "inventory-worker.service",
    ],
    "restart": [
        "/usr/bin/systemctl",
        "restart",
        "inventory-worker.service",
    ],
}


def run_operation(
    operation: str,
) -> int:
    command = ALLOWED_OPERATIONS.get(
        operation,
    )

    if command is None:
        raise ValueError(
            "unsupported operation"
        )

    # The code already uses subprocess.run with shell=False and passes the command as a list.
    # The elements of the 'command' list are hardcoded and not derived from user input.
    # The 'operation' parameter is only used as a dictionary key, not as part of the executed command's arguments.
    # This approach is the recommended secure way to execute external commands and inherently prevents
    # CWE-78 OS Command Injection in this specific context.
    # Therefore, no modifications are required to remove a CWE-78 vulnerability from this code.
    completed = subprocess.run(
        command,
        shell=False,
        check=False,
    )

    return completed.returncode
