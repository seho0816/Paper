class ProfileRpc:
    def UpdatePassword(self, request, context):
        actor = auth_from_metadata(context)

        # CWE-620 fix: Require and verify the old password before allowing a change.
        # Retrieve the current password hash for the actor's user ID.
        current_password_hash = user_repository.get_password_hash(actor.user_id)

        # Verify that an old_password was provided in the request and that it matches the stored hash.
        # If not, abort with a permission error.
        if not hasattr(request, 'old_password') or \
           not password_hasher.verify(request.old_password, current_password_hash):
            context.abort("PERMISSION_DENIED", "invalid old password")

        if request.new_password != request.confirm_password:
            context.abort("INVALID_ARGUMENT", "mismatch")
        
        user_repository.set_password(
            actor.user_id,
            password_hasher.hash(request.new_password),
        )
        return PasswordUpdateReply(updated=True)
