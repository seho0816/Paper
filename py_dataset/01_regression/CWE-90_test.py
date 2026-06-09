from ldap3 import Connection


def find_user(
    connection: Connection,
    username: str,
) -> list:
    search_filter = (
        "(uid="
        + username
        + ")"
    )
    connection.search(
        "ou=people,dc=example,dc=com",
        search_filter,
    )

    return connection.entries
