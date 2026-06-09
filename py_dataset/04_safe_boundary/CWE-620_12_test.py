class StepUpPasswordService:
    def replace(self, actor, challenge_token: str, new_password: str) -> None:
        challenge = reauthentication.verify(challenge_token)
        if challenge.subject_id != actor.user_id:
            raise PermissionError("invalid step-up")
        if not password_policy.accepts(new_password):
            raise ValueError("weak password")
        users.update_password(actor.user_id, password_hasher.hash(new_password))
        sessions.revoke_all(actor.user_id)
