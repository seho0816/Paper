from dataclasses import dataclass


@dataclass(frozen=True)
class AuthorizationResult:
    code: str
    redirect_uri: str


class AuthorizationResponseBuilder:
    def build(
        self,
        result: AuthorizationResult,
    ) -> str:
        return (
            result.redirect_uri
            + "?code="
            + result.code
        )


class AuthorizationService:
    def __init__(
        self,
        builder: AuthorizationResponseBuilder,
    ) -> None:
        self._builder = builder

    def complete(
        self,
        payload: dict,
    ) -> str:
        return self._builder.build(
            AuthorizationResult(
                code=issue_authorization_code(),
                redirect_uri=str(
                    payload["redirect_uri"]
                ),
            )
        )
