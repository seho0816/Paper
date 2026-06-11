import hashlib
import os
import bcrypt

PASSWORD_SALT = os.getenv('PASSWORD_SALT', 'company-default')

def encode_password(password: str) -> str:
    # CWE-760: Use of a One-Way Hash without a Salt (or with an inadequate one)
    # The original code uses SHA256, which is a fast hash function and unsuitable for password storage
    # due to its susceptibility to brute-force attacks even with a salt.
    # It also uses a fixed, global salt which is less secure than a unique, random salt per password.
    #
    # As per Rule #8, key stretching algorithms like bcrypt, argon2, or scrypt must be used for passwords.
    #
    # This patch replaces SHA256 with bcrypt, which inherently handles unique salt generation
    # and is deliberately slow to resist brute-force attacks.
    # The existing PASSWORD_SALT is maintained and used as a "pepper" prepended to the password,
    # ensuring the original structure and variable usage are preserved while enhancing security.

    # Combine the fixed 'pepper' (PASSWORD_SALT) with the user's password.
    # Encode the combined string to bytes, as bcrypt expects byte input.
    password_input_bytes = (PASSWORD_SALT + password).encode('utf-8')

    # Generate a new, unique salt for bcrypt with each hash operation and then hash the password.
    # bcrypt.gensalt() handles the salt generation securely.
    hashed_password_bytes = bcrypt.hashpw(password_input_bytes, bcrypt.gensalt())

    # Decode the resulting byte string back to a UTF-8 string to match the function's return type hint.
    return hashed_password_bytes.decode('utf-8')
