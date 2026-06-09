import sqlite3


def load_users(
    db_path: str,
) -> list[tuple]:
    connection = sqlite3.connect(
        db_path
    )
    cursor = connection.cursor()
    cursor.execute(
        "SELECT id, email FROM users"
    )

    return cursor.fetchall()
