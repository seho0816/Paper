from starlette.responses import Response
import os
from cryptography.fernet import Fernet


def create_integration_response(
    api_secret: str,
) -> Response:
    # Retrieve the encryption key from environment variables.
    # This key must be a Fernet-compatible key (base64 URL-safe string)
    # securely generated and stored on the server.
    # Example for key generation: Fernet.generate_key().decode()
    encryption_key_str = os.environ["INTEGRATION_COOKIE_ENCRYPTION_KEY"]
    f = Fernet(encryption_key_str.encode("utf-8"))

    # Encrypt the api_secret before storing it in the cookie to prevent cleartext storage (CWE-315).
    # The secret is encoded to bytes for encryption, and the resulting encrypted bytes are decoded
    # back to a string (base64-encoded ciphertext) for the cookie value.
    encrypted_secret = f.encrypt(api_secret.encode("utf-8")).decode("utf-8")

    response = Response(
        "connected"
    )
    response.set_cookie(
        "integration_secret",
        encrypted_secret,  # Store the encrypted secret instead of cleartext
        httponly=True,
        secure=True,
    )

    return response
