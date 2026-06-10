import os
from flask import Flask, request
from cryptography.fernet import Fernet

app = Flask(__name__)

# CWE-321: Use of Hard-coded Cryptographic Key
# The secret key should not be hard-coded directly in the source code.
# It should be loaded from a secure source, such as an environment variable,
# a configuration file (not committed to version control), or a key management system.
_secret_key_str = os.getenv("APP_SECRET_KEY")

if _secret_key_str is None:
    # Ensure the application fails loudly if the secret key is not configured.
    # This prevents the application from running with a missing or default key,
    # which would be insecure.
    raise ValueError("APP_SECRET_KEY environment variable not set. "
                     "Please set it to a URL-safe base64-encoded 32-byte key.")

# Fernet expects the key to be bytes. os.getenv returns a string.
# Base64 encoded keys generally contain only ASCII characters.
SECRET_KEY = _secret_key_str.encode('ascii')

@app.route("/encrypt")
def encrypt_value():
    value = request.args.get("value")

    # Note: If 'value' is None (e.g., no ?value= parameter), value.encode() will raise an AttributeError.
    # However, input validation for 'value' is not part of the CWE-321 fix and is outside the scope
    # of the strict rules for this patch.
    cipher = Fernet(SECRET_KEY)
    encrypted = cipher.encrypt(value.encode("utf-8"))

    return encrypted.decode("utf-8")
