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
            "recovery_question": account["recovery_question"],
            "recovery_answer": account["recovery_answer"],
            "mfa_backup_codes": account["mfa_backup_codes"],
        }
