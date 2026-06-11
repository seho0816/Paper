class LoginController:
    def complete(
        self,
        response,
        account_id: str,
    ):
        refresh_token = token_service.issue_refresh(
            account_id
        )
        response.set_cookie(
            "refresh",
            refresh_token,
            httponly=True,
            samesite="Strict",
            secure=True,
        )

        return response
