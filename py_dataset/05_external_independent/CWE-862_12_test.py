class UserAdministrationService:
    def SuspendUser(
        self,
        request,
        context,
    ):
        actor = authenticated_user_from_context(
            context,
        )
        suspend_account(
            request.user_id,
        )

        return {
            "suspended_by": actor["id"],
        }
