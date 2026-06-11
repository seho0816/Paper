from ldap3.utils.conv import escape_filter_chars

def find_objects(
    connection,
    object_class: str,
):
    # CWE-90: Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')
    # Escape the user-supplied object_class to prevent LDAP filter injection.
    safe_object_class = escape_filter_chars(object_class)
    ldap_filter = (
        "(objectClass="
        + safe_object_class
        + ")"
    )
    connection.search(
        "dc=example,dc=com",
        ldap_filter,
    )

    return connection.entries
