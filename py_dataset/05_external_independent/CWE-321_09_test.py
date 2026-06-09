from cryptography.hazmat.primitives import serialization

PRIVATE_KEY_PEM = b"""-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
-----END PRIVATE KEY-----
"""


def load_signing_key():
    return serialization.load_pem_private_key(
        PRIVATE_KEY_PEM,
        password=None,
    )
