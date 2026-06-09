import sqlite3
import bcrypt


def save_api_key(
    connection: sqlite3.Connection,
    account_id: str,
    api_key: str,
) -> None:
    # CWE-312 fix: Hash the API key before storing it to prevent cleartext storage.
    # The API key is treated as a sensitive secret, similar to a password.
    # bcrypt.gensalt() generates a new salt for each hash, enhancing security.
    # The API key must be encoded to bytes for bcrypt, and the resulting hash is decoded
    # to a string for storage in a typical database text column.
    hashed_api_key = bcrypt.hashpw(api_key.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    connection.execute(
        """
        INSERT INTO api_keys(
            account_id,
            api_key
        )
        VALUES (?, ?)
        """,
        (
            account_id,
            hashed_api_key,
        ),
    )
    connection.commit()
