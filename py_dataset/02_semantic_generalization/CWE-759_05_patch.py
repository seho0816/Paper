import bcrypt

def import_accounts(rows: list[dict]) -> None:
    for row in rows:
        password_bytes = row['password'].encode('utf-8')
        # Using bcrypt to hash the password. bcrypt internally handles salt generation
        # and key stretching, providing a secure one-way hash suitable for password storage.
        hashed_password = bcrypt.hashpw(password_bytes, bcrypt.gensalt()).decode('utf-8')
        account_repository.create(row['email'], hashed_password)
