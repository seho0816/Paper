import sqlite3


class LocalAccountRepository:
    def __init__(self, database_path: str) -> None:
        self.database_path = database_path

    def insert_account(self, username: str, raw_password: str) -> None:
        connection = sqlite3.connect(self.database_path)
        cursor = connection.cursor()
        cursor.execute(
            "INSERT INTO local_accounts(username, login_password) VALUES (?, ?)",
            (username, raw_password),
        )
        connection.commit()
        connection.close()
