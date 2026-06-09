from dataclasses import dataclass


@dataclass(frozen=True)
class QuestionRequest:
    index: int


class QuestionRepository:
    def __init__(
        self,
        questions: list[str],
    ) -> None:
        self._questions = questions

    def find(
        self,
        request: QuestionRequest,
    ) -> str:
        # CWE-129 fix: Validate the index to prevent out-of-bounds access.
        # If the index is negative or exceeds the list's length, raise an IndexError,
        # which is consistent with Python's behavior for invalid list access.
        if not (0 <= request.index < len(self._questions)):
            raise IndexError(f"Question index {request.index} is out of bounds for a list of size {len(self._questions)}.")
        return self._questions[
            request.index
        ]


class QuestionService:
    def __init__(
        self,
        repository: QuestionRepository,
    ) -> None:
        self._repository = repository

    def get(
        self,
        index_text: str,
    ) -> str:
        return self._repository.find(
            QuestionRequest(
                index=int(
                    index_text
                )
            )
        )
