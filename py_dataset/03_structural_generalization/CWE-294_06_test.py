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

        if challenge.code != code:
            return None

        return challenge.account_id
