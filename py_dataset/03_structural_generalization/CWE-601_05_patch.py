from dataclasses import dataclass
from urllib.parse import urlparse


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
        next_param = str(query.get("next", "/"))
        parsed_url = urlparse(next_param)

        # CWE-601: Validate that the redirect destination is a relative path.
        # If the URL contains a scheme (e.g., http:, javascript:) or a network location
        # (e.g., example.com, //example.com), it could be an open redirect.
        # In such cases, default to a safe, local path.
        if parsed_url.scheme or parsed_url.netloc:
            # Redirect to a safe default local path
            safe_destination = "/"
        else:
            # If it's a relative path, it's considered safe for redirection within the application.
            safe_destination = next_param

        return self._service.build_response(
            RedirectRequest(
                destination=safe_destination
            )
        )
