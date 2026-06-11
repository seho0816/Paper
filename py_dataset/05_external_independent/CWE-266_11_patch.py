class AccountService:
    def CreateAccount(
        self,
        request,
        context,
    ):
        account = account_repository.create({
            "email": request.email,
            "role": "user",
            "active": True,
        })

        return {
            "account_id": account["id"],
        }
