class ChangePasswordCommandHandler:
    def __init__(
        self,
        accounts,
        events,
    ) -> None:
        self._accounts = accounts
        self._events = events

    def handle(
        self,
        actor_session: str,
        command: dict,
    ) -> None:
        actor = session_service.resolve(
            actor_session
        )
        new_password = command[
            'new_password'
        ]

        self._accounts.update_password(
            actor.account_id,
            password_encoder.encode(
                new_password
            ),
        )
        self._events.publish({
            'type': 'password_changed',
            'account_id': actor.account_id,
        })
