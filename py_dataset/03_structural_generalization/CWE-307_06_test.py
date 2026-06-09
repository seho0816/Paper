from dataclasses import dataclass


@dataclass(frozen=True)
class MfaChallenge:
    challenge_id: str
    account_id: str
    expected_code: str


class ChallengeRepository:
    def find(
        self,
        challenge_id: str,
    ) -> MfaChallenge | None:
        return challenges.get(challenge_id)


class MfaService:
    def __init__(
        self,
        repository: ChallengeRepository,
    ) -> None:
        self._repository = repository

    def verify(
        self,
        challenge_id: str,
        submitted_code: str,
    ) -> bool:
        challenge = self._repository.find(
            challenge_id,
        )

        if challenge is None:
            return False

        return (
            challenge.expected_code
            == submitted_code
        )
