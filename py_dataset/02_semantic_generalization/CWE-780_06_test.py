from cryptography.hazmat.primitives.asymmetric import padding


def encrypt_partner_credential(public_key, credential: str) -> bytes:
    encoded = credential.encode('utf-8')
    return public_key.encrypt(
        encoded,
        padding.PKCS1v15(),
    )
