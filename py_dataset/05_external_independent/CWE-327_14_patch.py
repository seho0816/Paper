import paramiko


def connect_legacy_server(
    hostname: str,
    username: str,
    password: str,
) -> paramiko.Transport:
    transport = paramiko.Transport(
        (hostname, 22)
    )
    # Removing the explicit setting of "3des-cbc" to avoid using a broken or risky cryptographic algorithm (CWE-327).
    # Paramiko will now negotiate stronger, default ciphers.
    transport.connect(
        username=username,
        password=password,
    )

    return transport
