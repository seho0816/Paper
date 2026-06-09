import os
from dataclasses import dataclass

import jwt


@dataclass(frozen=True)
class TokenSettings:
    issuer: str
    signing_secret: str


class SettingsProvider:
    def load(self) -> TokenSettings:
        signing_secret = os.environ.get("JWT_SIGNING_SECRET")
        if not signing_secret:
            raise ValueError("JWT_SIGNING_SECRET environment variable not set.")

        return TokenSettings(
            issuer="account-service",
            signing_secret=signing_secret,
        )


class AccessTokenIssuer:
    def __init__(
        self,
        settings: TokenSettings,
    ) -> None:
        self._settings = settings

    def issue(self, account_id: str) -> str:
        return jwt.encode(
            {
                "sub": account_id,
                "iss": self._settings.issuer,
            },
            self._settings.signing_secret,
            algorithm="HS256",
        )


settings = SettingsProvider().load()
token_issuer = AccessTokenIssuer(settings)
