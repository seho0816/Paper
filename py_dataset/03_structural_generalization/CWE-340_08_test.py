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
        code = f'INV-{offset}'
        self._invitation_store.save({
            'email': message['email'],
            'team_id': message['team_id'],
            'code': code,
        })
