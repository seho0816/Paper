import mysql.connector


def load_inventory(
    configuration: dict,
) -> list[tuple]:
    connection = mysql.connector.connect(
        **configuration
    )
    cursor = connection.cursor()
    cursor.execute(
        "SELECT sku, quantity FROM inventory"
    )

    return cursor.fetchall()
