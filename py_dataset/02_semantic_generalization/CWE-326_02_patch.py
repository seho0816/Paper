from cryptography.hazmat.primitives.asymmetric import dsa


def create_document_signing_key():
    return dsa.generate_private_key(
        key_size=2048,
    )
