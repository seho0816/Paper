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
        # CWE-352: 인자 추가 없이 내부에서 CSRF 상태 검증 로직 추가
        expected_state = get_expected_state(account_id)
        if not callback.state or callback.state != expected_state:
            raise ValueError("CSRF state mismatch or missing")

        token = self._client.exchange(callback.code)
        save_connected_account(
            account_id,
            token,
        )