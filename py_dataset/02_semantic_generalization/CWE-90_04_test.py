def find_objects(
    connection,
    object_class: str,
):
    ldap_filter = (
        "(objectClass="
        + object_class
        + ")"
    )
    connection.search(
        "dc=example,dc=com",
        ldap_filter,
    )

    return connection.entries
