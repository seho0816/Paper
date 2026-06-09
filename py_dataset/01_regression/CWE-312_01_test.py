import sqlite3


def save_api_key(
    connection: sqlite3.Connection,
    account_id: str,
    api_key: str,
) -> None:
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
            api_key,
        ),
    )
    connection.commit()
