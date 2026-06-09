class AccountService:
    def ChangePassword(
        self,
        request,
        context,
    ):
        update_password_hash(
            request.account_id,
            request.new_password_hash,
        )

        return {
            "changed": True,
        }
