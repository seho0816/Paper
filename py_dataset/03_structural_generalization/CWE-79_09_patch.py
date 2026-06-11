from dataclasses import dataclass

from markupsafe import escape


@dataclass(frozen=True)
class ProfileUpdate:
    account_id: str
    biography: str


class ProfileRepository:
    def __init__(self) -> None:
        self._profiles: dict[str, str] = {}

    def save(self, update: ProfileUpdate) -> None:
        self._profiles[update.account_id] = update.biography

    def find_biography(self, account_id: str) -> str:
        return self._profiles[account_id]


class ProfileViewService:
    def __init__(self, repository: ProfileRepository) -> None:
        self._repository = repository

    def render(self, account_id: str) -> str:
        biography = self._repository.find_biography(account_id)
        return f"<section>{escape(biography)}</section>"
