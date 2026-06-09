class ApiKeyAuthenticationService:
    def authenticate(
        self,
        api_key: str,
    ) -> dict | None:
        credential = api_key_repository.find(
            api_key
        )

        if credential is None:
            return None

        account = account_repository.find(
            credential["account_id"]
        )

        return {
            "account_id": account["id"],
            "scopes": credential["scopes"],
        }
