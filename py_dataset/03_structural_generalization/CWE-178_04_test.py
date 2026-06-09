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
        return (
            pair.submitted.lower()
            == pair.expected.lower()
        )


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
