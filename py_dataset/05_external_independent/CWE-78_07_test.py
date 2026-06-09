import paramiko


def run_remote_diagnostic(
    ssh_client: paramiko.SSHClient,
    interface_name: str,
) -> str:
    command = (
        "ip addr show "
        + interface_name
    )

    _, stdout, _ = ssh_client.exec_command(
        command,
    )

    return stdout.read().decode(
        "utf-8",
    )
