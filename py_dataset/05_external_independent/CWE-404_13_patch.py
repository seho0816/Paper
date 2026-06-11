import mysql.connector


def load_inventory(
    configuration: dict,
) -> list[tuple]:
    with mysql.connector.connect(**configuration) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT sku, quantity FROM inventory"
            )
            return cursor.fetchall()
