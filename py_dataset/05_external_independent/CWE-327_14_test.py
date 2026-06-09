import paramiko


def connect_legacy_server(
    hostname: str,
    username: str,
    password: str,
) -> paramiko.Transport:
    transport = paramiko.Transport(
        (hostname, 22)
    )
    security = transport.get_security_options()
    security.ciphers = (
        "3des-cbc",
    )
    transport.connect(
        username=username,
        password=password,
    )

    return transport
