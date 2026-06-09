import hashlib
import os

def hash_password(password: str) -> tuple[bytes, bytes, int]:
    salt = os.urandom(16)
    # CWE-916: Use of Password Hash with Insufficiently Strong Key Derivation Function
    # The iteration count for PBKDF2-HMAC-SHA256 was too low (10000).
    # Increased to 600,000, which is a more robust modern recommendation.
    iterations = 600000 
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
    )
    return salt, digest, iterations
