from dataclasses import dataclass


@dataclass(frozen=True)
class SigningRequest:
    payload: bytes
    key_id: str


class SigningService:
    def sign(
        self,
        request: SigningRequest,
    ) -> bytes:
        key = key_repository.find(
            request.key_id
        )

        return signer.sign(
            key["secret"],
            request.payload,
        )
