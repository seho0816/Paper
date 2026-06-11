import bcrypt

def update_password(account_id: str, password: str) -> None:
    encoded_password = password.encode('utf-8')
    # Generate a unique salt for each password and hash it using bcrypt.
    # bcrypt automatically includes the salt and cost factor in the output hash string.
    hashed_password_bytes = bcrypt.hashpw(encoded_password, bcrypt.gensalt())
    # Store the bcrypt hash as a UTF-8 string.
    credential_repository.replace(account_id, hashed_password_bytes.decode('utf-8'))
