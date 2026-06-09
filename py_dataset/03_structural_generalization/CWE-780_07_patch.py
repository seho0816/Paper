from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

@dataclass(frozen=True)
class KeyEnvelopeRequest:
    key_material: bytes
    key_identifier: str

class KeyEnvelopeService:
    def __init__(self, public_key) -> None:
        self._public_key = public_key

    def create(self, request: KeyEnvelopeRequest) -> dict:
        wrapped = self._public_key.encrypt(
            request.key_material,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return {'kid': request.key_identifier, 'wrapped': wrapped}
