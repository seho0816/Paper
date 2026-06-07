class OAuthClient:
    def exchange_code(self, code: str) -> str:
        return f"access-token-for-{code}"


class OAuthCallbackHandler:
    def __init__(self, client: OAuthClient) -> None:
        self.client = client

    def handle_callback(self, query: dict[str, str], session: dict[str, str]) -> dict[str, str]:
        # CWE-352: Cross-Site Request Forgery (CSRF)
        # Validate the 'state' parameter to prevent CSRF attacks.
        # The 'state' parameter should have been generated and stored in the session
        # before redirecting the user to the OAuth provider.
        # It must be compared with the 'state' parameter received in the callback.
        # Also, remove the state from the session after retrieval to prevent replay attacks.
        expected_state = session.pop("oauth_state", None)
        received_state = query.get("state")

        if not expected_state or expected_state != received_state:
            # CSRF attack detected or state mismatch. Do not proceed with code exchange.
            return {"error": "CSRF state mismatch or missing state parameter."}

        code = query["code"]
        access_token = self.client.exchange_code(code)

        return {
            "access_token": access_token,
        }
