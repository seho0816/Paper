from ldap3 import Connection, Server


def connect_directory(
    host: str,
    username: str,
    password: str,
) -> Connection:
    server = Server(
        host,
        port=636,
        use_ssl=True,
    )
    connection = Connection(
        server,
        user=username,
        password=password,
        auto_bind=True,
    )

    return connection
