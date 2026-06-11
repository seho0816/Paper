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
        normalized = unicodedata.normalize(
            "NFKC",
            request.username,
        )
        self._policy.validate(
            normalized
        )
        save_user(
            normalized
        )

        return normalized

# Placeholder for an assumed external function
def save_user(username: str) -> None:
    # In a real application, this would save the user to a database or similar.
    pass
