import regex
from dataclasses import dataclass


@dataclass(frozen=True)
class MessageFilter:
    expression: str


class MessageRepository:
    def find_all(
        self,
    ) -> list[str]:
        return database.load_messages()


class MessageFilterService:
    def __init__(
        self,
        repository: MessageRepository,
    ) -> None:
        self._repository = repository

    def filter(
        self,
        request: MessageFilter,
    ) -> list[str]:
        pattern = regex.compile(
            request.expression,
            timeout=1,
        )

        return [
            message
            for message in self._repository.find_all()
            if pattern.search(message)
        ]
