import bcrypt

def create_sqlalchemy_account(
    session,
    email: str,
    password: str,
    cipher,
):
    # CWE-257: Storing Passwords in a Recoverable Format.
    # The original code encrypted the password, allowing it to be decrypted.
    # This has been replaced with a secure, one-way hashing function (bcrypt).
    # The 'cipher' parameter is kept in the signature as per strict rules, but it is no longer used.
    
    # Generate a salt and hash the password using bcrypt.
    # password.encode("utf-8") converts the string password to bytes,
    # which is required by bcrypt.hashpw.
    hashed_password_bytes = bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt()
    )
    # The result of bcrypt.hashpw is bytes; decode it to a UTF-8 string for storage.
    hashed_password_str = hashed_password_bytes.decode("utf-8")

    account = Account(
        email=email,
        # Store the securely hashed password instead of an encrypted (recoverable) one.
        encrypted_password=hashed_password_str,
    )
    session.add(
        account
    )
    session.commit()

    return account
