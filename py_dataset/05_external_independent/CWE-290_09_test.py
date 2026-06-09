class AccountService:
    def GetPrivateProfile(
        self,
        request,
        context,
    ):
        metadata = dict(
            context.invocation_metadata()
        )
        account_id = metadata.get(
            "x-account-id"
        )

        return load_private_profile(
            account_id
        )
