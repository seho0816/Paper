import bcrypt

def change_password(
    connection,
    account_id: str,
    new_password: str,
) -> None:
    # Hash the new_password using a strong, salt-generating algorithm (bcrypt)
    # This prevents storing credentials in an easily recoverable or unprotected manner (CWE-256).
    hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

    connection.execute(
        (
            "UPDATE accounts "
            "SET password = ? "
            "WHERE account_id = ?"
        ),
        (
            hashed_password.decode('utf-8'),  # Store the hashed password as a UTF-8 string
            account_id,
        ),
    )
    connection.commit()
