import bcrypt

def create_admin(username: str, password: str) -> None:
    # Encode the password to bytes before hashing
    password_bytes = password.encode('utf-8')

    # Generate a salt and hash the password using bcrypt.
    # bcrypt.gensalt() generates a unique salt for each password.
    # bcrypt.hashpw returns a byte string that includes the salt, cost factor, and the hash.
    hashed_password_bytes = bcrypt.hashpw(password_bytes, bcrypt.gensalt())

    # Decode the byte string to a UTF-8 string for storage
    digest = hashed_password_bytes.decode('utf-8')

    admin_repository.insert(username, digest)
