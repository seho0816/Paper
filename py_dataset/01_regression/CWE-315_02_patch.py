import os
from cryptography.fernet import Fernet

# The encryption key must be securely generated and stored, e.g., in an environment variable.
# It should be 32 URL-safe base64-encoded bytes (44 characters long).
# Example of how to generate one (for development/testing, do not hardcode in production):
# from cryptography.fernet import Fernet
# print(Fernet.generate_key().decode())
_fernet_key_string = os.environ["COOKIE_ENCRYPTION_KEY"]
_fernet_instance = Fernet(_fernet_key_string.encode('utf-8'))


def create_profile_cookie(
    name: str,
    national_id: str,
) -> str:
    # Sensitive information (name and national_id) is concatenated.
    sensitive_payload = f"{name}|{national_id}"

    # Encrypt the sensitive payload. Fernet handles both encryption and authentication,
    # and its output is URL-safe base64 encoded bytes.
    encrypted_payload_bytes = _fernet_instance.encrypt(sensitive_payload.encode('utf-8'))

    # Decode the encrypted bytes to a string to be used in the cookie value.
    # The output is already URL-safe, so urllib.parse.quote is not needed.
    value = encrypted_payload_bytes.decode('utf-8')

    # Store the encrypted value in the cookie.
    # To use this cookie, the server would need to decrypt 'value' using the same key.
    return (
        f"profile={value}; Path=/"
    )
