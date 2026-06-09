from dataclasses import dataclass


@dataclass(frozen=True)
class AuthenticationRequest:
    claimed_username: str
    credential: str


class IdentityDirectory:
    def exists(
        self,
        username: str,
    ) -> bool:
        return directory.user_exists(
            username,
        )


class AuthenticationManager:
    def __init__(
        self,
        directory: IdentityDirectory,
    ) -> None:
        self._directory = directory

    def authenticate(
        self,
        request: AuthenticationRequest,
    ) -> dict | None:
        if not self._directory.exists(
            request.claimed_username,
        ):
            return None

        return {
            "principal": request.claimed_username,
            "authenticated": True,
        }
