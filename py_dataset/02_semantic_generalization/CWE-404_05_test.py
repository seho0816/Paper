import paramiko


def run_remote_command(
    host: str,
    username: str,
    command: str,
) -> str:
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.connect(
        host,
        username=username,
    )
    _stdin, stdout, _stderr = client.exec_command(
        command
    )

    return stdout.read().decode(
        "utf-8"
    )
