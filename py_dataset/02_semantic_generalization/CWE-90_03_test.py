def search_directory(
    connection,
    department: str,
    role: str,
):
    ldap_filter = (
        "(&(department="
        + department
        + ")(role="
        + role
        + "))"
    )
    connection.search(
        DIRECTORY_BASE,
        ldap_filter,
    )

    return connection.entries
