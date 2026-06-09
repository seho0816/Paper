from dataclasses import dataclass


@dataclass(frozen=True)
class LinkRequest:
    headers: dict
    token: str


class ResetLinkBuilder:
    def build(
        self,
        request: LinkRequest,
    ) -> str:
        host = request.headers.get(
            "Host"
        )

        return (
            f"https://{host}/reset"
            f"?token={request.token}"
        )


class RecoveryService:
    def __init__(
        self,
        builder: ResetLinkBuilder,
    ) -> None:
        self._builder = builder

    def issue(
        self,
        request: LinkRequest,
    ) -> str:
        return self._builder.build(
            request
        )
