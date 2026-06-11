class RecoveryService:
    def RequestReset(
        self,
        request,
        context,
    ):
        account = find_account(
            request.email
        )

        if account is not None:
            send_reset_email(
                account["email"]
            )

        # To prevent account enumeration (CWE-204),
        # always return a consistent message, regardless of whether the account
        # was found or not. This prevents attackers from distinguishing between
        # existing and non-existing email addresses.
        return {
            "status": "EMAIL_SENT",
        }
