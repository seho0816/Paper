import bcrypt

async def register_async(
    connection,
    email: str,
    password: str,
) -> int:
    # CWE-256: Unprotected Storage of Credentials
    # Hash the password using bcrypt before storing it to protect credentials.
    # bcrypt.hashpw expects bytes and returns bytes, so encode/decode is necessary.
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    return await connection.fetchval(
        (
            "INSERT INTO users"
            "(email, password) "
            "VALUES ($1, $2) "
            "RETURNING id"
        ),
        email,
        hashed_password, # Use the hashed password
    )
