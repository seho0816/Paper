from ldap3 import Connection
from ldap3.utils.conv import escape_filter_chars


def authenticate(
    connection: Connection,
    username: str,
    password: str,
) -> bool:
    # CWE-90: Improper Neutralization of Special Elements used in an LDAP Query (LDAP Injection)
    # The fix is to escape any special characters in the user-provided
    # username and password before incorporating them into the LDAP search filter.
    # This prevents an attacker from manipulating the query structure.
    escaped_username = escape_filter_chars(username)
    escaped_password = escape_filter_chars(password)

    search_filter = (
        f"(&(uid={escaped_username})"
        f"(userPassword={escaped_password}))"
    )
    connection.search(
        "ou=people,dc=example,dc=com",
        search_filter,
    )

    return bool(
        connection.entries
    )
