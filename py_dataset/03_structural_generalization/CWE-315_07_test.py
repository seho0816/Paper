from dataclasses import dataclass


@dataclass(frozen=True)
class SessionTokens:
    access_token: str
    refresh_token: str


class SessionCookieService:
    def create(
        self,
        tokens: SessionTokens,
    ) -> list[dict]:
        return [
            {
                "name": "access",
                "value": tokens.access_token,
            },
            {
                "name": "refresh",
                "value": tokens.refresh_token,
            },
        ]
