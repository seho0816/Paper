import hmac
from dataclasses import dataclass


@dataclass(frozen=True)
class TokenPair:
    submitted: str
    expected: str


class TokenVerifier:
    def verify(
        self,
        pair: TokenPair,
    ) -> bool:
        # To prevent timing attacks, use hmac.compare_digest for constant-time comparison.
        # Ensure both strings are converted to lowercase and then encoded to bytes
        # to maintain the original case-insensitive functionality.
        submitted_bytes = pair.submitted.lower().encode('utf-8')
        expected_bytes = pair.expected.lower().encode('utf-8')
        return hmac.compare_digest(submitted_bytes, expected_bytes)


class RecoveryService:
    def __init__(
        self,
        verifier: TokenVerifier,
    ) -> None:
        self._verifier = verifier

    def validate(
        self,
        submitted: str,
        expected: str,
    ) -> bool:
        return self._verifier.verify(
            TokenPair(
                submitted=submitted,
                expected=expected,
            )
        )
