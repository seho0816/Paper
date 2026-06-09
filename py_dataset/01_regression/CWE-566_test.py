import sqlite3


def load_invoice_by_primary_key(db_path: str, invoice_pk: int) -> tuple | None:
    connection = sqlite3.connect(db_path)
    cursor = connection.cursor()
    cursor.execute(
        'SELECT id, user_id, amount FROM invoices WHERE id = ?',
        (invoice_pk,),
    )
    row = cursor.fetchone()
    connection.close()
    return row
