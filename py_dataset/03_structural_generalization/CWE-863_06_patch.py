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
        # CWE-863: Incorrect Authorization.
        # The original logic `user.get("role") == document.required_role`
        # incorrectly handles cases where `document.required_role` is an empty string.
        # If `document.required_role` is an empty string (`""`), it typically implies
        # that no specific role is required for access (e.g., public access).
        # The original code would only grant access if the user's role was also `""`,
        # which is an unusual and often unintended requirement for public resources.

        # Fix: If `document.required_role` is an empty string, grant access
        # based solely on this condition, as no specific role is mandated.
        if document.required_role == "":
            return True

        # Otherwise, a specific role is required.
        # Retrieve the user's role. If the 'role' key is missing, user_role will be None.
        user_role = user.get("role")

        # Compare the user's role with the document's required role.
        # If user_role is None and document.required_role is a non-empty string,
        # the comparison will correctly evaluate to False, denying access.
        return user_role == document.required_role


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
