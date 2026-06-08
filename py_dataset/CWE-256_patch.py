import sqlite3
import bcrypt


class LocalAccountRepository:
    def __init__(self, database_path: str) -> None:
        self.database_path = database_path

    def insert_account(self, username: str, raw_password: str) -> None:
        connection = sqlite3.connect(self.database_path)
        cursor = connection.cursor()

        # CWE-256: Unprotected Storage of Credentials
        # Hash the raw password before storing it.
        password_bytes = raw_password.encode('utf-8')
        hashed_password = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
        hashed_password_str = hashed_password.decode('utf-8')

        cursor.execute(
            "INSERT INTO local_accounts(username, login_password) VALUES (?, ?)",
            (username, hashed_password_str),
        )
        connection.commit()
        connection.close()
