def members_of_group(
    connection,
    group_name: str,
):
    expression = (
        "(memberOf=cn="
        + group_name
        + ",ou=groups,dc=example,dc=com)"
    )
    connection.search(
        "ou=people,dc=example,dc=com",
        expression,
    )

    return connection.entries
