class AuthenticationService:
    def Login(
        self,
        request,
        context,
    ):
        account = find_account(
            request.username
        )

        # CWE-304: Missing Critical Step in Multiple-Step Authentication.
        # A critical step in authentication is to verify the account's state
        # (e.g., if it exists and is enabled) BEFORE attempting password verification
        # and session creation. Failing to do so can allow login to disabled accounts
        # or lead to security bypasses.
        # This check ensures the account is valid and enabled for login.
        # A generic error message "invalid credentials" is used for both
        # account not found, disabled, or incorrect password to prevent user enumeration.
        if not account or not account.get("is_enabled", False):
            # If 'account' is None (not found) or 'is_enabled' is False (or missing, defaulting to False),
            # then the authentication fails.
            raise PermissionError(
                "invalid credentials"
            )

        if not verify_password(
            request.password,
            account["password_hash"],
        ):
            raise PermissionError(
                "invalid credentials"
            )

        return {
            "session_id": create_session(
                account["id"]
            ),
        }
