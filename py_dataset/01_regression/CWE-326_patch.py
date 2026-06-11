from cryptography.hazmat.primitives.asymmetric import rsa


def create_signing_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,  # CWE-326 fix: Increased key_size to an adequate strength (2048 bits is a common minimum recommendation).
    )
