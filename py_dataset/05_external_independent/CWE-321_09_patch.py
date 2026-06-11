import os
from cryptography.hazmat.primitives import serialization


def load_signing_key():
    # CWE-321: Use of Hard-coded Cryptographic Key vulnerability removed.
    # The private key is no longer hard-coded in the source.
    # Instead, it is retrieved from an environment variable named 'PRIVATE_KEY_PEM_ENV'.
    # This environment variable must contain the full PEM-encoded private key string,
    # including the BEGIN and END markers (e.g., "-----BEGIN PRIVATE KEY-----...-----END PRIVATE KEY-----").
    private_key_pem_str = os.environ["PRIVATE_KEY_PEM_ENV"]

    # The serialization.load_pem_private_key function expects bytes.
    # PEM data is typically ASCII, so encoding as 'ascii' or 'utf-8' is appropriate.
    private_key_pem_bytes = private_key_pem_str.encode('ascii')

    return serialization.load_pem_private_key(
        private_key_pem_bytes,
        password=None,
    )
