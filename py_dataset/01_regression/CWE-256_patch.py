import sqlite3
import bcrypt


def create_user(
    db_path: str,
    email: str,
    password: str,
) -> None:
    # CWE-256 fix: Hash the password before storing it.
    # The password must be encoded to bytes before hashing, and the resulting hash
    # is decoded to a string for storage in a TEXT column.
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

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
            hashed_password,  # Store the hashed password instead of the plaintext password
        ),
    )
    connection.commit()
    connection.close()
