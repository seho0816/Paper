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
        
        # Calculate the expected HMAC digest in raw bytes
        expected_digest_bytes = hmac.new(
            self._secret,
            normalized,
            hashlib.sha256,
        ).digest() # Changed from .hexdigest() to .digest()

        # Decode the provided signature string from hexadecimal to bytes.
        # This explicit decoding ensures that the comparison is performed on the
        # raw byte values of the digest, which is more robust and prevents
        # issues if the string representation is subtly malformed or interpreted
        # differently. It also implicitly validates the format of the signature.
        try:
            provided_signature_bytes = bytes.fromhex(payload.signature)
        except ValueError:
            # If the signature string is not valid hexadecimal, it cannot be verified.
            return False

        # Use hmac.compare_digest for constant-time comparison of the byte digests.
        return hmac.compare_digest(
            expected_digest_bytes,
            provided_signature_bytes,
        )
