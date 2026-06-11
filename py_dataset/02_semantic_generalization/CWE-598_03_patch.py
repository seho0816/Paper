import os
from cryptography.fernet import Fernet

def build_session_redirect(
    public_origin: str,
    session_id: str,
) -> str:
    # CWE-598: Information Exposure Through Query Strings in GET Request
    # The original code directly exposed the session_id in the URL query string.
    # This sensitive information can be logged by servers, proxies, and browsers,
    # leading to potential session fixation or hijacking if captured.

    # To mitigate this, the session_id is encrypted before being placed in the URL.
    # The encryption key must be securely managed and retrieved from an environment variable.
    encryption_key = os.environ.get("ENCRYPTION_KEY")

    if not encryption_key:
        # It is critical that an encryption key is available for security.
        # If not set, raise an error to prevent insecure operation and enforce proper configuration.
        raise ValueError("ENCRYPTION_KEY environment variable not set. Cannot build secure session redirect.")

    # Initialize Fernet, a symmetric encryption scheme that provides authenticated encryption.
    # Fernet tokens are URL-safe and include a timestamp, nonce, and HMAC.
    try:
        f = Fernet(encryption_key.encode())
    except Exception as e:
        raise ValueError(f"Invalid ENCRYPTION_KEY provided: {e}")

    # Encrypt the session_id. The result is a URL-safe base64 encoded string.
    encrypted_session_id = f.encrypt(session_id.encode()).decode()

    # Construct the redirect URL with the encrypted session_id.
    # The raw session_id is no longer exposed in the query string.
    return (
        public_origin
        + "/continue?session_id="
        + encrypted_session_id
    )
