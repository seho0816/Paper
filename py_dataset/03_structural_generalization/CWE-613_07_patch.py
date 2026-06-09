from dataclasses import dataclass


@dataclass(frozen=True)
class LogoutRequest:
    account_id: str
    refresh_token: str


class LogoutService:
    _invalidated_tokens = set()

    def logout(
        self,
        request: LogoutRequest,
    ) -> dict:
        LogoutService._invalidated_tokens.add(request.refresh_token)

        return {
            "delete_cookies": [
                "access_token",
                "refresh_token",
            ],
            "account_id": request.account_id,
        }
