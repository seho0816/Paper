from ldap3 import Connection
from ldap3.utils.conv import escape_filter_chars


def find_user(
    connection: Connection,
    username: str,
) -> list:
    escaped_username = escape_filter_chars(username)
    search_filter = (
        "(uid="
        + escaped_username
        + ")"
    )
    connection.search(
        "ou=people,dc=example,dc=com",
        search_filter,
    )

    return connection.entries
