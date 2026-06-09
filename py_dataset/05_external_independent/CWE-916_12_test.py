import hashlib
import secrets

def enroll_terminal_operator(operator_id: str, password: str) -> None:
    salt = secrets.token_bytes(12)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 2500)
    terminal_directory.save(operator_id, salt, digest)
