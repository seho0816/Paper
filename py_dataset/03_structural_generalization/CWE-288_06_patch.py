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

        # CWE-288: Authentication Bypass Using an Alternate Path or Channel
        # Ensure the retrieved API key is active and valid before proceeding.
        # An inactive, revoked, or expired key should not grant access.
        # Assuming the 'credential' object/dictionary has an 'is_active' attribute/key.
        if not credential.get("is_active", False):
            return None

        account = account_repository.find(
            credential["account_id"]
        )

        return {
            "account_id": account["id"],
            "scopes": credential["scopes"],
        }
