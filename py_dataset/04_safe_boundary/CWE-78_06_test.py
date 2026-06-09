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

    completed = subprocess.run(
        command,
        shell=False,
        check=False,
    )

    return completed.returncode
