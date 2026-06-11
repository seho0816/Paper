from ldap3.utils.conv import escape_filter_chars

def members_of_group(
    connection,
    group_name: str,
):
    # Escape special characters in group_name to prevent LDAP injection (CWE-90)
    escaped_group_name = escape_filter_chars(group_name)
    expression = (
        "(memberOf=cn="
        + escaped_group_name
        + ",ou=groups,dc=example,dc=com)"
    )
    connection.search(
        "ou=people,dc=example,dc=com",
        expression,
    )

    return connection.entries
