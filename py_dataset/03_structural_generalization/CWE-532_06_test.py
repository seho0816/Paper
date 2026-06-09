import logging
from dataclasses import dataclass


@dataclass(frozen=True)
class OAuthToken:
    access_token: str
    refresh_token: str
    expires_in: int


class OAuthClient:
    def exchange(
        self,
        code: str,
    ) -> OAuthToken:
        return exchange_authorization_code(
            code,
        )


class OAuthService:
    def __init__(
        self,
        client: OAuthClient,
    ) -> None:
        self._client = client
        self._logger = logging.getLogger(
            "oauth"
        )

    def connect(
        self,
        code: str,
    ) -> OAuthToken:
        token = self._client.exchange(code)
        self._logger.info(
            "oauth token=%s refresh=%s",
            token.access_token,
            token.refresh_token,
        )

        return token
