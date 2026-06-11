import hashlib
import os

def hash_password(password: str) -> tuple[bytes, bytes, int]:
    salt = os.urandom(16)
    # CWE-916: Use of Password Hash With Insufficiently Strong Hashing Algorithm
    # The original iteration count (1000) for PBKDF2-HMAC-SHA256 is too low
    # for modern security standards and would be vulnerable to brute-force attacks.
    # Increasing the iteration count makes the hashing algorithm stronger.
    iterations = 600000  # A significantly higher iteration count for improved security
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
    )
    return salt, digest, iterations
