from dataclasses import dataclass


@dataclass(frozen=True)
class RedirectRequest:
    destination: str


class RedirectService:
    def build_response(
        self,
        request: RedirectRequest,
    ) -> tuple[int, dict[str, str]]:
        return (
            302,
            {
                "Location": request.destination,
            },
        )


class LoginController:
    def __init__(
        self,
        service: RedirectService,
    ) -> None:
        self._service = service

    def complete(
        self,
        query: dict,
    ):
        return self._service.build_response(
            RedirectRequest(
                destination=str(
                    query.get("next", "/")
                )
            )
        )
