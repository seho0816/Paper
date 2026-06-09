class ProfileRpc:
    def UpdatePassword(self, request, context):
        actor = auth_from_metadata(context)
        if request.new_password != request.confirm_password:
            context.abort("INVALID_ARGUMENT", "mismatch")
        user_repository.set_password(
            actor.user_id,
            password_hasher.hash(request.new_password),
        )
        return PasswordUpdateReply(updated=True)
