import sqlite3

async def load_account(db_path: str, account_id: str) -> dict:
    connection = sqlite3.connect(
        db_path,
        timeout=5,
    )
    try:
        # CWE-1322: Improper Protection of Sensitive Data by Incomplete Blacklisting
        # The 'account_id' is expected to be a numeric identifier.
        # Although parameterized queries prevent SQL injection,
        # passing a non-numeric string when an integer is expected can
        # lead to unexpected behavior or potential bypasses in systems
        # that rely on strict numeric IDs.
        # Explicitly converting to an integer ensures that only valid numeric IDs are processed.
        try:
            validated_account_id = int(account_id)
        except ValueError:
            # If the account_id cannot be converted to an integer, it's invalid input.
            # Return an empty dict to indicate no account found for such an ID.
            return {}

        row = connection.execute(
            'SELECT id, email FROM accounts WHERE id = ?',
            (validated_account_id,),
        ).fetchone()

        if row:
            return {
                'id': row[0],
                'email': row[1],
            }
        else:
            # If no account is found, return an empty dictionary.
            return {}
    finally:
        connection.close()
