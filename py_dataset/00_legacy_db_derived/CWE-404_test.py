import sqlite3


class UserReportRepository:
    def load_emails(self, database_path: str) -> list[str]:
        connection = sqlite3.connect(database_path)
        cursor = connection.cursor()
        cursor.execute("SELECT email FROM users WHERE active = 1")

        return [row[0] for row in cursor.fetchall()]
