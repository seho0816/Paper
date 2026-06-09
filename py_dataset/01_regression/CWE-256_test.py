import sqlite3


def create_user(
    db_path: str,
    email: str,
    password: str,
) -> None:
    connection = sqlite3.connect(
        db_path
    )
    cursor = connection.cursor()
    cursor.execute(
        (
            "INSERT INTO users"
            "(email, password) "
            "VALUES (?, ?)"
        ),
        (
            email,
            password,
        ),
    )
    connection.commit()
    connection.close()
