from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


def protect_export_key(public_key, export_key: bytes, export_id: str) -> dict:
    wrapped_key = public_key.encrypt(
        export_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return {
        'export_id': export_id,
        'wrapped_key': wrapped_key,
    }
