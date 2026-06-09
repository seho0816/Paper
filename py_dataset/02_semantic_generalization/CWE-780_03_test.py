from cryptography.hazmat.primitives.asymmetric import padding


def protect_export_key(public_key, export_key: bytes, export_id: str) -> dict:
    wrapped_key = public_key.encrypt(
        export_key,
        padding.PKCS1v15(),
    )
    return {
        'export_id': export_id,
        'wrapped_key': wrapped_key,
    }
