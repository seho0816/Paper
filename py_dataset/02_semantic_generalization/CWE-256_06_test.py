async def register_async(
    connection,
    email: str,
    password: str,
) -> int:
    return await connection.fetchval(
        (
            "INSERT INTO users"
            "(email, password) "
            "VALUES ($1, $2) "
            "RETURNING id"
        ),
        email,
        password,
    )
