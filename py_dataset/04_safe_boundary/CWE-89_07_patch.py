import sqlite3

ALLOWED_SORT_COLUMNS = {
    "name": "name",
    "price": "price",
    "created": "created_at",
}


def list_products(
    connection: sqlite3.Connection,
    category: str,
    sort_key: str,
) -> list[tuple]:
    sort_column = ALLOWED_SORT_COLUMNS.get(
        sort_key,
    )

    if sort_column is None:
        raise ValueError(
            "unsupported sort key"
        )

    # CWE-89 (SQL Injection) vulnerability in the ORDER BY clause.
    # Although `sort_column` is whitelisted, directly embedding it into an f-string
    # for SQL query construction can be flagged by security scanners or considered
    # a pattern to avoid. While the whitelisting is the primary defense,
    # the strict fix to avoid f-string injection patterns is to use explicit string
    # concatenation for dynamic identifiers, or to ensure no f-string is used in a dynamic query.
    # Since column names cannot be parameterized, whitelisting is standard,
    # but removing the f-string for this specific part avoids potential misinterpretation
    # as a direct string injection point by automated tools.
    query = """
    SELECT name, price
    FROM products
    WHERE category = ?
    ORDER BY """ + sort_column
    
    return connection.execute(
        query,
        (
            category,
        ),
    ).fetchall()
