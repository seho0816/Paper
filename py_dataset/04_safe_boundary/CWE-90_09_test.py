from ldap3.utils.conv import escape_filter_chars


def find_user(
    connection,
    username: str,
):
    safe_username = escape_filter_chars(
        username
    )
    expression = (
        f"(uid={safe_username})"
    )
    connection.search(
        DIRECTORY_BASE,
        expression,
    )

    return connection.entries
