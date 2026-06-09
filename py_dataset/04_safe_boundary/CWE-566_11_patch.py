import sqlite3


def load_invoice_for_user(
    db_path: str,
    current_user_id: str,
    invoice_pk: int,
) -> tuple | None:
    connection = sqlite3.connect(db_path)
    cursor = connection.cursor()
    cursor.execute(
        'SELECT id, user_id, amount FROM invoices WHERE id = ? AND user_id = ?',
        (invoice_pk, current_user_id),
    )
    row = cursor.fetchone()
    connection.close()
    return row

