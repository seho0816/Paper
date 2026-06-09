import psycopg


def load_orders(
    database_url: str,
) -> list[tuple]:
    connection = psycopg.connect(
        database_url
    )
    cursor = connection.cursor()
    cursor.execute(
        "SELECT order_id, total FROM orders"
    )

    return cursor.fetchall()
