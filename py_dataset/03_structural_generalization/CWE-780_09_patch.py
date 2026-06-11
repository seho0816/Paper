from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

class EncryptedCredentialRepository:
    def __init__(self, database, public_key) -> None:
        self._database = database
        self._public_key = public_key

    def save(self, account_id: str, secret: bytes) -> None:
        encrypted = self._public_key.encrypt(
            secret,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            ),
        )
        self._database.insert_credential(
            account_id,
            encrypted,
        )
