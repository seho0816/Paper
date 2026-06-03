class OAuthClient:
    def exchange_code(self, code: str) -> str:
        return f"access-token-for-{code}"


class OAuthCallbackHandler:
    def __init__(self, client: OAuthClient) -> None:
        self.client = client

    def handle_callback(self, query: dict[str, str], session: dict[str, str]) -> dict[str, str]:
        code = query["code"]
        access_token = self.client.exchange_code(code)

        return {
            "access_token": access_token,
        }
