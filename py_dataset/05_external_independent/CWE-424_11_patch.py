class AccountService:
    def ChangePassword(
        self,
        request,
        context,
    ):
        # CWE-424 fix: Implement proper access control to ensure that only the
        # authenticated user can change their own password.
        # This assumes that the 'context' object contains the identifier of
        # the currently authenticated user (e.g., context.authenticated_user_id).
        # Replace 'context.authenticated_user_id' with the actual mechanism
        # for retrieving the authenticated user's ID in your environment.
        authenticated_user_id = context.authenticated_user_id

        if str(request.account_id) != str(authenticated_user_id):
            raise PermissionError("Unauthorized: Cannot change password for another user's account.")

        update_password_hash(
            request.account_id,
            request.new_password_hash,
        )

        return {
            "changed": True,
        }
