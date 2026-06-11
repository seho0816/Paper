import paramiko
import re
import shlex

def run_remote_diagnostic(
    ssh_client: paramiko.SSHClient,
    interface_name: str,
) -> str:
    if not re.fullmatch(r'^[a-zA-Z0-9_-]+$', interface_name):
        return ""

    safe_interface = shlex.quote(interface_name)
    command = "ip addr show %s" % safe_interface

    _, stdout, _ = ssh_client.exec_command(command)

    return stdout.read().decode("utf-8")