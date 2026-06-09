from ldap3 import Connection


def find_account(
    connection: Connection,
    email: str,
) -> list:
    expression = "(mail={})".format(
        email
    )
    connection.search(
        "ou=accounts,dc=example,dc=com",
        expression,
    )

    return connection.entries
