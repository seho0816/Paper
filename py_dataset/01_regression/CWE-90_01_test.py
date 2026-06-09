from ldap3 import Connection


def authenticate(
    connection: Connection,
    username: str,
    password: str,
) -> bool:
    search_filter = (
        f"(&(uid={username})"
        f"(userPassword={password}))"
    )
    connection.search(
        "ou=people,dc=example,dc=com",
        search_filter,
    )

    return bool(
        connection.entries
    )
