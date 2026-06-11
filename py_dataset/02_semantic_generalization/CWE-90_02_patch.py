from ldap3 import Connection
from ldap3.utils.conv import escape_filter_chars


def find_account(
    connection: Connection,
    email: str,
) -> list:
    # CWE-90 fix: Escape special characters in the email to prevent LDAP injection.
    # The ldap3.utils.conv.escape_filter_chars function correctly neutralizes
    # characters that could manipulate the LDAP filter.
    escaped_email = escape_filter_chars(email)
    expression = "(mail={})".format(
        escaped_email
    )
    connection.search(
        "ou=accounts,dc=example,dc=com",
        expression,
    )

    return connection.entries
