import sqlite3


def read_user(
    connection: sqlite3.Connection,
    user_id: str,
) -> tuple | None:
    cursor = connection.execute(
        """
        SELECT id, email
        FROM users
        WHERE id = ?
        """,
        (
            user_id,
        ),
    )

    return cursor.fetchone()

