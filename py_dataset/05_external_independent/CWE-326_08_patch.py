import paramiko


def create_ssh_host_key():
    return paramiko.RSAKey.generate(
        bits=2048,
    )
