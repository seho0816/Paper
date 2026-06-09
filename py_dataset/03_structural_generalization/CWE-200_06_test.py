from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class UserRecord:
    user_id: str
    email: str
    password_hash: str
    recovery_answer: str
    internal_notes: str


class UserRepository:
    def find(
        self,
        user_id: str,
    ) -> UserRecord:
        return database.load_user(
            user_id,
        )


class UserQueryService:
    def __init__(
        self,
        repository: UserRepository,
    ) -> None:
        self._repository = repository

    def get_profile(
        self,
        user_id: str,
    ) -> dict:
        record = self._repository.find(
            user_id,
        )

        return asdict(record)
