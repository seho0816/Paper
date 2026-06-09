from ldap3.utils.conv import escape_filter_chars


ALLOWED_ATTRIBUTES = {
    "uid",
    "mail",
    "employeeNumber",
}


def search_by_attribute(
    connection,
    attribute: str,
    value: str,
):
    if attribute not in ALLOWED_ATTRIBUTES:
        raise ValueError(
            "unsupported attribute"
        )

    safe_value = escape_filter_chars(
        value
    )
    expression = (
        f"({attribute}={safe_value})"
    )
    connection.search(
        DIRECTORY_BASE,
        expression,
    )

    return connection.entries

