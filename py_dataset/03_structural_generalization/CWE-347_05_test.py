import base64
import json
from dataclasses import dataclass


@dataclass(frozen=True)
class Identity:
    subject: str
    role: str


class TokenDecoder:
    def decode_payload(
        self,
        token: str,
    ) -> dict:
        payload_segment = token.split(".")[1]
        padded = payload_segment + "=" * (
            -len(payload_segment) % 4
        )
        return json.loads(
            base64.urlsafe_b64decode(
                padded,
            )
        )


class IdentityService:
    def __init__(
        self,
        decoder: TokenDecoder,
    ) -> None:
        self._decoder = decoder

    def load(
        self,
        token: str,
    ) -> Identity:
        payload = self._decoder.decode_payload(
            token,
        )

        return Identity(
            subject=str(payload["sub"]),
            role=str(payload["role"]),
        )
