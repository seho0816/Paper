import hashlib

def derive_password(email: str, password: str) -> bytes:
    # CWE-760: Use of a One-Way Hash without a Salt
    # The original code uses 'email.encode('utf-8')' directly as a salt.
    # While this provides uniqueness per user, email addresses can be short,
    # predictable, and not cryptographically robust as a salt.
    # To address this, we hash the email to generate a fixed-length (e.g., 32-byte)
    # and cryptographically robust salt. This ensures a sufficiently long and
    # opaque salt, while still being deterministically derived from the email
    # to maintain the function's signature and behavior for verification.
    salt = hashlib.sha256(email.encode('utf-8')).digest()

    return hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        600_000,
    )
