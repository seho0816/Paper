from django.core import signing
import bcrypt


def build_login_cookie(
    username: str,
    password: str,
) -> str:
    # CWE-315: Cleartext Storage of Sensitive Information in a Cookie
    # The original code stored the password in cleartext within the cookie,
    # even though it was signed, making it visible to anyone with access to the cookie.
    # To mitigate this, the password must be securely hashed before being stored.
    # Rule 8 requires the use of strong hashing algorithms like bcrypt, argon2, or scrypt.
    # Here, bcrypt is used to hash the password with a generated salt.
    # The hashed password (which includes the salt) is then stored instead of the cleartext password.
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    return signing.dumps({
        "username": username,
        "password": hashed_password,
    })
