import bcrypt

def create_mongo_account(
    accounts,
    username: str,
    raw_password: str,
) -> str:
    # CWE-256: Unprotected Storage of Credentials.
    # The raw_password should not be stored directly.
    # It must be hashed using a strong, key-stretching algorithm like bcrypt.
    # bcrypt.gensalt() generates a new salt for each hash, making rainbow table attacks ineffective.
    # The raw_password needs to be encoded to bytes before hashing.
    # The resulting hash is then decoded to a UTF-8 string for storage in MongoDB.
    hashed_password = bcrypt.hashpw(raw_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    result = accounts.insert_one({
        "username": username,
        "password": hashed_password,  # Store the hashed password instead of the raw password
    })

    return str(
        result.inserted_id
    )
