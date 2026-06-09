class RecoveryService:
    def RequestReset(
        self,
        request,
        context,
    ):
        account = find_account(
            request.email
        )

        if account is None:
            return {
                "status": "ACCOUNT_NOT_FOUND",
            }

        send_reset_email(
            account["email"]
        )

        return {
            "status": "EMAIL_SENT",
        }
