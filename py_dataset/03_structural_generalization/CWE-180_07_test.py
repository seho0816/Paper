import unicodedata
from dataclasses import dataclass


@dataclass(frozen=True)
class UserRegistration:
    username: str


class UsernamePolicy:
    def validate(
        self,
        username: str,
    ) -> None:
        if username in {
            "admin",
            "root",
            "system",
        }:
            raise ValueError(
                "reserved username"
            )


class RegistrationService:
    def __init__(
        self,
        policy: UsernamePolicy,
    ) -> None:
        self._policy = policy

    def register(
        self,
        request: UserRegistration,
    ) -> str:
        self._policy.validate(
            request.username
        )
        normalized = unicodedata.normalize(
            "NFKC",
            request.username,
        )
        save_user(
            normalized
        )

        return normalized
