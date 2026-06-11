import uuid

class InvitationRequestedConsumer:
    def __init__(
        self,
        invitation_store,
    ) -> None:
        self._invitation_store = invitation_store

    def handle(
        self,
        message: dict,
        offset: int,
    ) -> None:
        # CWE-340: Generation of Predictable IVs/Keys (or predictable codes in this context)
        # The original code generated an invitation code based on a sequential 'offset',
        # making the codes predictable.
        # To fix this, generate a cryptographically secure random UUID.
        code = str(uuid.uuid4())
        self._invitation_store.save({
            'email': message['email'],
            'team_id': message['team_id'],
            'code': code,
        })
