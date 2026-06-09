import hashlib
import os
import base64

def store_password(account_id: int, password: str) -> None:
    iterations = 600_000
    # CWE-760 Fix: Generate a cryptographically secure random salt
    # The original code used account_id as salt, which is predictable and defeats the purpose of salting.
    # A random, unique salt for each password makes precomputation attacks significantly harder.
    salt = os.urandom(16) # 16 bytes (128 bits) is a commonly recommended salt length.

    # Encode password explicitly with utf-8 before hashing
    password_bytes = password.encode('utf-8')
    digest = hashlib.pbkdf2_hmac('sha256', password_bytes, salt, iterations)

    # To store the password securely, the salt and iteration count must be stored along with the hash.
    # A common and robust way is to combine them into a single string, often base64-encoded for binary components.
    # This string will be saved as the 'digest' in the repository.
    encoded_salt = base64.urlsafe_b64encode(salt).decode('ascii')
    encoded_digest = base64.urlsafe_b64encode(digest).decode('ascii')
    
    # Format: $algorithm$iterations$salt(base64)$digest(base64)
    # Using URL-safe base64 encoding to avoid issues with special characters in storage.
    combined_hash_string = f"$pbkdf2_hmac_sha256${iterations}${encoded_salt}${encoded_digest}"

    credential_repository.save(account_id, combined_hash_string)
