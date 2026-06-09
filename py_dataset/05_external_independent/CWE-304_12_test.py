class AuthenticationService:
    def Login(
        self,
        request,
        context,
    ):
        account = find_account(
            request.username
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
