import hashlib
import hmac
import json
from dataclasses import dataclass


@dataclass(frozen=True)
class SignedPayload:
    raw_body: bytes
    signature: str


class JsonNormalizer:
    def normalize(
        self,
        raw_body: bytes,
    ) -> bytes:
        parsed = json.loads(
            raw_body,
        )

        return json.dumps(
            parsed,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")


class PayloadVerifier:
    def __init__(
        self,
        normalizer: JsonNormalizer,
        secret: bytes,
    ) -> None:
        self._normalizer = normalizer
        self._secret = secret

    def verify(
        self,
        payload: SignedPayload,
    ) -> bool:
        normalized = self._normalizer.normalize(
            payload.raw_body,
        )
        expected = hmac.new(
            self._secret,
            normalized,
            hashlib.sha256,
        ).hexdigest()

        return hmac.compare_digest(
            expected,
            payload.signature,
        )
