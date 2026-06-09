class AccountService:
    def ChangeEmail(self, request, context):
        metadata = dict(context.invocation_metadata())
        context.principal = {
            "user_id": metadata["x-user-id"],
            "role": metadata.get("x-role", "user"),
            "tenant_id": metadata["x-tenant-id"],
        }
        return update_email(context.principal, request.new_email)
