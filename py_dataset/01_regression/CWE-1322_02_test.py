import sqlite3

async def load_account(db_path: str, account_id: str) -> dict:
    connection = sqlite3.connect(
        db_path,
        timeout=5,
    )
    try:
        row = connection.execute(
            'SELECT id, email FROM accounts WHERE id = ?',
            (account_id,),
        ).fetchone()
        return {
            'id': row[0],
            'email': row[1],
        }
    finally:
        connection.close()
