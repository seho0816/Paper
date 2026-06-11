import bcrypt

def import_accounts(
    rows: list[dict],
) -> int:
    imported = 0

    for row in rows:
        # CWE-256 fix: Hash the password before storing it.
        # bcrypt is used as a strong, key-stretching hashing algorithm.
        # Passwords must be encoded to bytes for bcrypt.hashpw,
        # and the resulting hash is decoded back to a string for storage.
        hashed_password = bcrypt.hashpw(row["password"].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        user_repository.create({
            "username": row["username"],
            "password": hashed_password, # Store the hashed password
        })
        imported += 1

    return imported
