from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric import padding

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
            padding.PKCS1v15(),
        )
        return {'kid': request.key_identifier, 'wrapped': wrapped}
