import sqlite3
import os


def load_invoice_by_primary_key(db_path: str, invoice_pk: int) -> tuple | None:
    # CWE-566: Improper Link Resolution Before File Access ('Time-of-check Time-of-use' Race Condition)
    # The original code directly uses db_path, which could be a symbolic link manipulated by an attacker
    # to point to an arbitrary file (e.g., /etc/passwd). This could lead to information disclosure.
    # To mitigate this, we ensure that the provided db_path is not a symbolic link.
    # If symlinks are intended to be followed, a more complex solution involving path canonicalization
    # and validation against a trusted base directory would be required.
    # However, without a defined trusted base directory and to adhere to strict rules (no new features/dummy values),
    # explicitly disallowing symbolic links for critical file access is the most direct and safest fix
    # to prevent "Improper Link Resolution".
    if os.path.islink(db_path):
        raise ValueError("Symbolic links are not allowed for the database path due to security concerns.")

    connection = sqlite3.connect(db_path)
    cursor = connection.cursor()
    cursor.execute(
        'SELECT id, user_id, amount FROM invoices WHERE id = ?',
        (invoice_pk,),
    )
    row = cursor.fetchone()
    connection.close()
    return row
