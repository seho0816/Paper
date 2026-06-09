from dataclasses import dataclass


@dataclass(frozen=True)
class Document:
    document_id: str
    required_role: str
    content: str


class DocumentPolicy:
    def can_read(
        self,
        user: dict,
        document: Document,
    ) -> bool:
        return (
            user.get("role")
            == document.required_role
        )


class DocumentService:
    def __init__(
        self,
        policy: DocumentPolicy,
    ) -> None:
        self._policy = policy

    def read(
        self,
        user: dict,
        document: Document,
    ) -> str:
        if not self._policy.can_read(
            user,
            document,
        ):
            raise PermissionError(
                "denied"
            )

        return document.content
