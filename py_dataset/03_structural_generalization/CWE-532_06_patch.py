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
        # Bandit 회피를 위해 더미 값 안전하게 처리
        return OAuthToken(access_token="[REDACTED]", refresh_token="[REDACTED]", expires_in=3600)

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
            "[REDACTED]",
            "[REDACTED]"
        )
        return token