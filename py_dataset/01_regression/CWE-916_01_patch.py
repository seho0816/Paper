import hashlib
import os

def hash_password(password: str) -> tuple[bytes, bytes, int]:
    salt = os.urandom(16)
    # CWE-916 (Insufficiently Strong One-Way Hash) fix:
    # Increased the iteration count significantly to improve resistance against brute-force attacks.
    # Modern recommendations for PBKDF2-HMAC-SHA256 suggest iteration counts in the hundreds of thousands or more
    # to achieve a target delay of approximately 100-200ms on typical CPUs, making it sufficiently strong.
    iterations = 600000 # Increased from 5000 to meet modern security recommendations.
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
    )
    return salt, digest, iterations
