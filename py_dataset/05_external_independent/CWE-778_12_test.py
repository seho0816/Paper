class DirectoryAdminService:
    def DisableAccount(self, request, context):
        account_repository.disable(
            request.account_id
        )
        session_repository.revoke_all(
            request.account_id
        )
        return {'disabled': True}
