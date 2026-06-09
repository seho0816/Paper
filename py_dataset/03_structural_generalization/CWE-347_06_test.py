import jwt
from dataclasses import dataclass


@dataclass(frozen=True)
class VerificationRequest:
    token: str
    verification_key: str


class AlgorithmSelector:
    def select(
        self,
        token: str,
    ) -> str:
        return str(
            jwt.get_unverified_header(
                token,
            )["alg"]
        )


class TokenVerifier:
    def __init__(
        self,
        selector: AlgorithmSelector,
    ) -> None:
        self._selector = selector

    def verify(
        self,
        request: VerificationRequest,
    ) -> dict:
        algorithm = self._selector.select(
            request.token,
        )

        return jwt.decode(
            request.token,
            request.verification_key,
            algorithms=[algorithm],
        )
