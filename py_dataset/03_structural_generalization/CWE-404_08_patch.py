import sqlite3


class UserRepository:
    def __init__(
        self,
        db_path: str,
    ) -> None:
        self._db_path = db_path

    def find_all(
        self,
    ) -> list[tuple]:
        with sqlite3.connect(self._db_path) as connection:
            cursor = connection.cursor()
            cursor.execute(
                "SELECT id, email FROM users"
            )

            return cursor.fetchall()
