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

        # CWE-391 fix: Process the error codes/results from sub-operations.
        # Assuming that `_tokens.revoke` and `_sessions.remove_for` return a truthy
        # value on success and a falsy value (e.g., None, False, empty object) on failure.
        token_op_success = bool(token_result)
        session_op_success = bool(session_result)

        overall_success = token_op_success and session_op_success

        # Publish 'logout.completed' event only if both token revocation and session removal were successful.
        # This aligns the event's meaning with the `success` status reported by the workflow.
        if overall_success:
            self._events.publish('logout.completed', {'account_id': command.account_id})

        return {'success': overall_success, 'details': [token_result, session_result]}
