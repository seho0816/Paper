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
