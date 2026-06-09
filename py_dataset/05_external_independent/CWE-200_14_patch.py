class AccountService:
    def GetAccountDetails(
        self,
        request,
        context,
    ):
        account = load_account(
            request.account_id,
        )

        return {
            "account_id": account["id"],
            "email": account["email"],
        }
