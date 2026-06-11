import ldap.filter

def resolve_group_members(
    _root,
    _info,
    group_name: str,
) -> list:
    escaped_group_name = ldap.filter.escape_filter_chars(group_name)
    expression = (
        "(memberOf=cn="
        + escaped_group_name
        + ",ou=groups,dc=example,dc=com)"
    )
    ldap_connection.search(
        PEOPLE_BASE,
        expression,
    )

    return [
        serialize_entry(entry)
        for entry in ldap_connection.entries
    ]
