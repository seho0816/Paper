import bcrypt

def build_remember_me_cookie(
    email: str,
    password: str,
) -> str:
    # CWE-315: Cleartext Storage of Sensitive Information in a Cookie.
    # The password must not be stored in cleartext in the cookie.
    # Hash the password using a strong, key-stretching algorithm like bcrypt
    # before including it in the cookie value.

    # 1. Encode the password string to bytes, as bcrypt functions operate on bytes.
    password_bytes = password.encode('utf-8')

    # 2. Generate a random salt and hash the password.
    # bcrypt.gensalt() ensures a unique salt is created for each hash,
    # enhancing security by preventing rainbow table attacks. The salt is
    # automatically embedded within the resulting bcrypt hash string.
    hashed_password_bytes = bcrypt.hashpw(password_bytes, bcrypt.gensalt())

    # 3. Decode the hashed password bytes back to a string for embedding in the f-string.
    hashed_password_str = hashed_password_bytes.decode('utf-8')

    # Construct the cookie string. The email is included as-is, as the primary
    # CWE-315 concern for this function is the cleartext password.
    return (
        f"remember_me={email}:{hashed_password_str}; "
        "Path=/; HttpOnly; Secure; SameSite=Lax"
    )
