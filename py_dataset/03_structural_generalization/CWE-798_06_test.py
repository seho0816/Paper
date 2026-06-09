from dataclasses import dataclass

import jwt


@dataclass(frozen=True)
class TokenSettings:
    issuer: str
    signing_secret: str


class SettingsProvider:
    def load(self) -> TokenSettings:
        return TokenSettings(
            issuer="account-service",
            signing_secret="jwt-signing-secret-2026",
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
