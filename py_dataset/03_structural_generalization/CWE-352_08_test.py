from dataclasses import dataclass


@dataclass(frozen=True)
class OAuthCallback:
    code: str
    state: str | None


class OAuthClient:
    def exchange(self, code: str) -> dict:
        return exchange_code_for_token(code)


class AccountConnectionService:
    def __init__(self, client: OAuthClient) -> None:
        self._client = client

    def connect(
        self,
        account_id: str,
        callback: OAuthCallback,
    ) -> None:
        token = self._client.exchange(callback.code)
        save_connected_account(
            account_id,
            token,
        )
