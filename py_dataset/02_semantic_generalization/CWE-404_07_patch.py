import psycopg


def load_orders(
    database_url: str,
) -> list[tuple]:
    with psycopg.connect(database_url) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT order_id, total FROM orders"
            )
            return cursor.fetchall()
