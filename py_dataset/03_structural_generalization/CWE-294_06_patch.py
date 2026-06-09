import hmac
from dataclasses import dataclass


@dataclass
class OtpChallenge:
    challenge_id: str
    account_id: str
    code: str


class OtpRepository:
    def find(
        self,
        challenge_id: str,
    ) -> OtpChallenge | None:
        # Assuming otp_challenges is a global or class-level dictionary
        # In a real application, this would interact with a database
        return otp_challenges.get(
            challenge_id
        )


class OtpService:
    def __init__(
        self,
        repository: OtpRepository,
    ) -> None:
        self._repository = repository

    def verify(
        self,
        challenge_id: str,
        code: str,
    ) -> str | None:
        challenge = self._repository.find(
            challenge_id
        )

        if challenge is None:
            return None

        # CWE-294: Authentication Bypass by Primary Weakness (Timing Attack)
        # Using hmac.compare_digest to prevent timing attacks when comparing secrets.
        # This function performs a constant-time comparison.
        if not hmac.compare_digest(challenge.code, code):
            return None

        return challenge.account_id
