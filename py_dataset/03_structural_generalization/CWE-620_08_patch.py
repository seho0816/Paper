import session_service
import password_encoder

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
        # CWE-620 Fix: Implement verification for the password change.
        # This requires the current_password to be provided in the command.
        # The _accounts service is then responsible for verifying this current_password
        # against the stored hash before applying the new password.
        current_password = command[
            'current_password'
        ]

        # The _accounts.update_password method is modified to accept
        # the current_password for verification purposes.
        # It is assumed that _accounts.update_password will perform
        # the necessary verification and raise an error if the current_password is incorrect.
        self._accounts.update_password(
            actor.account_id,
            current_password, # Added for verification by the _accounts service
            password_encoder.encode(
                new_password
            ),
        )
        self._events.publish({
            'type': 'password_changed',
            'account_id': actor.account_id,
        })
