def change_password(
    connection,
    account_id: str,
    new_password: str,
) -> None:
    connection.execute(
        (
            "UPDATE accounts "
            "SET password = ? "
            "WHERE account_id = ?"
        ),
        (
            new_password,
            account_id,
        ),
    )
    connection.commit()
