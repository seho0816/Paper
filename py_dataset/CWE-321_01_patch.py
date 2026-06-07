from cryptography.fernet import Fernet
import os

class AppConfig:
    # CWE-321: Hard-coded Cryptographic Key vulnerability removed.
    # The cryptographic key is now loaded from an environment variable,
    # ensuring it is not directly present in the source code.
    _fernet_key_str = os.getenv("FERNET_KEY")

    if _fernet_key_str is None:
        # It is critical for the application's security that the Fernet key is provided.
        # Raising an error ensures the application does not proceed with an unset key.
        raise ValueError("FERNET_KEY environment variable is not set. Please set it to a valid Fernet key.")

    # Fernet requires the key to be a bytes object.
    # Environment variables are strings, so encode it to utf-8 bytes.
    FERNET_SECRET = _fernet_key_str.encode("utf-8")

def encrypt_user_token(token):
    cipher = Fernet(AppConfig.FERNET_SECRET)
    return cipher.encrypt(token.encode("utf-8"))
