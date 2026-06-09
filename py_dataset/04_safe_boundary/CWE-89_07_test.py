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

    query = f"""
    SELECT name, price
    FROM products
    WHERE category = ?
    ORDER BY {sort_column}
    """

    return connection.execute(
        query,
        (
            category,
        ),
    ).fetchall()
