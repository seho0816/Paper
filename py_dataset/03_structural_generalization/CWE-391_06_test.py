from dataclasses import dataclass


@dataclass(frozen=True)
class LogoutCommand:
    account_id: str
    refresh_token: str


class LogoutWorkflow:
    def __init__(self, tokens, sessions, events) -> None:
        self._tokens = tokens
        self._sessions = sessions
        self._events = events

    def execute(self, command: LogoutCommand) -> dict:
        token_result = self._tokens.revoke(command.refresh_token)
        session_result = self._sessions.remove_for(command.account_id)
        self._events.publish('logout.completed', {'account_id': command.account_id})
        return {'success': True, 'details': [token_result, session_result]}
