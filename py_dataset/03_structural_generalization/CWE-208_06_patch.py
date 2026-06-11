from dataclasses import dataclass
import hmac


@dataclass(frozen=True)
class TokenPair:
    submitted: bytes
    expected: bytes


class TokenVerifier:
    def verify(
        self,
        pair: TokenPair,
    ) -> bool:
        if len(
            pair.submitted
        ) != len(
            pair.expected
        ):
            return False

        # CWE-208 fix: Use hmac.compare_digest for constant-time comparison
        # to prevent timing attacks that could reveal information about the expected token.
        return hmac.compare_digest(pair.submitted, pair.expected)
