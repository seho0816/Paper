import os
from cryptography.fernet import Fernet

def cache_refresh_token(redis_client, account_id: str, refresh_token: str) -> None:
    encryption_key = os.environ.get("REFRESH_TOKEN_ENCRYPTION_KEY")
    if not encryption_key:
        raise ValueError("REFRESH_TOKEN_ENCRYPTION_KEY environment variable not set or is empty. Please set a secure Fernet key.")
    
    # Initialize Fernet with the secure key
    # The key must be URL-safe base64-encoded bytes.
    # It's generally recommended to initialize Fernet once per application lifecycle
    # for performance, but for a self-contained fix within the function signature,
    # re-initialization is done here.
    fernet = Fernet(encryption_key.encode('utf-8'))

    # Encrypt the refresh_token before storing it to protect sensitive data (CWE-524)
    # Fernet operates on bytes, so encode the refresh_token string.
    # The output of encrypt() is bytes, so decode it back to string for Redis storage if needed,
    # or leave as bytes if the Redis client handles it directly.
    encrypted_token = fernet.encrypt(refresh_token.encode('utf-8')).decode('utf-8')

    redis_client.setex(
        f"refresh:{account_id}",
        86400,
        encrypted_token,
    )
