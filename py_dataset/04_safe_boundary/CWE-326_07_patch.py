from cryptography.hazmat.primitives.asymmetric import ed25519


def create_signing_key():
    return ed25519.Ed25519PrivateKey.generate()

