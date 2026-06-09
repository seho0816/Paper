import hashlib
import secrets

def enroll_terminal_operator(operator_id: str, password: str) -> None:
    salt = secrets.token_bytes(12)
    # Replaced hashlib.pbkdf2_hmac with hashlib.scrypt for a stronger Key Derivation Function.
    # Parameters n, r, p are set to common secure values for scrypt.
    # dklen is set to 32 bytes to match the typical output size of SHA-256 for compatibility.
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**16, r=8, p=1, dklen=32)
    terminal_directory.save(operator_id, salt, digest)
