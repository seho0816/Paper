import os
from cryptography.fernet import Fernet

def create_access_cookie(
    access_token: str,
) -> str:
    # CWE-315: Cleartext Storage of Sensitive Information in a Cookie
    # The access_token is sensitive information and should not be stored in cleartext.
    # To mitigate this, the access_token is encrypted before being stored in the cookie.
    # A symmetric encryption key (Fernet key) must be securely managed and provided
    # via an environment variable. For example, a key can be generated once
    # using `Fernet.generate_key().decode()` and then set as an environment variable
    # like `export COOKIE_ENCRYPTION_KEY="<your_generated_key_here>"`.

    encryption_key_b64 = os.environ["COOKIE_ENCRYPTION_KEY"]
    
    cipher_suite = Fernet(encryption_key_b64.encode('utf-8'))
    
    # Encrypt the access_token. Fernet expects bytes for encryption.
    encrypted_token_bytes = cipher_suite.encrypt(access_token.encode('utf-8'))
    
    # Convert the encrypted bytes to a URL-safe string for the cookie value.
    encrypted_token_str = encrypted_token_bytes.decode('utf-8')

    return (
        "access_token="
        + encrypted_token_str
        + "; Path=/; HttpOnly; Secure"
    )
