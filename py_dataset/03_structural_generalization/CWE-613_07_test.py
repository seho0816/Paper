from dataclasses import dataclass


@dataclass(frozen=True)
class LogoutRequest:
    account_id: str
    refresh_token: str


class LogoutService:
    def logout(
        self,
        request: LogoutRequest,
    ) -> dict:
        return {
            "delete_cookies": [
                "access_token",
                "refresh_token",
            ],
            "account_id": request.account_id,
        }
