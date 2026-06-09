from ldap3.utils.conv import escape_filter_chars


def search_directory(
    connection,
    department: str,
    role: str,
):
    safe_department = escape_filter_chars(
        department
    )
    safe_role = escape_filter_chars(
        role
    )
    expression = (
        f"(&(department={safe_department})"
        f"(role={safe_role}))"
    )
    connection.search(
        DIRECTORY_BASE,
        expression,
    )

    return connection.entries
