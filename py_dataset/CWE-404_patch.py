import sqlite3


class UserReportRepository:
    def load_emails(self, database_path: str) -> list[str]:
        with sqlite3.connect(database_path) as connection:
            cursor = connection.cursor()
            cursor.execute("SELECT email FROM users WHERE active = 1")

            return [row[0] for row in cursor.fetchall()]
