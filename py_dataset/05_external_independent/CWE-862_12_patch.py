import grpc


class UserAdministrationService:
    def SuspendUser(
        self,
        request,
        context,
    ):
        actor = authenticated_user_from_context(
            context,
        )

        # CWE-862: Missing Authorization
        # Ensure that the authenticated actor has the necessary permissions
        # (e.g., 'admin' role) to suspend a user account.
        if "admin" not in actor.get("roles", []):
            context.abort(grpc.StatusCode.PERMISSION_DENIED, "Caller does not have permission to suspend users.")

        suspend_account(
            request.user_id,
        )

        return {
            "suspended_by": actor["id"],
        }
