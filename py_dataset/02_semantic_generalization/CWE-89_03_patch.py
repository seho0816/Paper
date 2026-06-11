from mysql.connector import MySQLConnection


def load_invoice(
    connection: MySQLConnection,
    invoice_number: str,
) -> list[tuple]:
    query = (
        "SELECT invoice_number, total "
        "FROM invoices WHERE invoice_number = %s"
    )

    cursor = connection.cursor()
    cursor.execute(query, (invoice_number,))
    rows = cursor.fetchall()
    cursor.close()

    return rows
