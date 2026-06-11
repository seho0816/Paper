from ldap3.utils.conv import escape_filter_chars


def search_directory(
    connection,
    department: str,
    role: str,
):
    # CWE-90: Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')
    # Sanitize user inputs to prevent LDAP filter injection.
    escaped_department = escape_filter_chars(department)
    escaped_role = escape_filter_chars(role)

    ldap_filter = (
        "(&(department="
        + escaped_department
        + ")(role="
        + escaped_role
        + "))"
    )
    connection.search(
        DIRECTORY_BASE,  # DIRECTORY_BASE is expected to be defined elsewhere in the application context.
        ldap_filter,
    )

    return connection.entries
