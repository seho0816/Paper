from dataclasses import dataclass


@dataclass(frozen=True)
class OAuthLogin:
    browser_session_id: str
    authorization_code: str


class OAuthLoginService:
    def complete(
        self,
        request: OAuthLogin,
    ) -> str:
        identity = exchange_code(
            request.authorization_code,
        )
        sessions[
            request.browser_session_id
        ]["identity"] = identity

        return request.browser_session_id
