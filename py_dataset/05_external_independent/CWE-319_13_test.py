from ldap3 import Connection, Server


def connect_directory(
    host: str,
    username: str,
    password: str,
) -> Connection:
    server = Server(
        host,
        port=389,
        use_ssl=False,
    )
    connection = Connection(
        server,
        user=username,
        password=password,
        auto_bind=True,
    )

    return connection
