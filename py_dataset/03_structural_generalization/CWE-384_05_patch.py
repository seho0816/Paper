import secrets
from dataclasses import dataclass


@dataclass(frozen=True)
class OAuthLogin:
    browser_session_id: str
    authorization_code: str


class OAuthLoginService:
    def complete(
        self,
        request: OAuthLogin,
    ) -> str:
        identity = exchange_code(
            request.authorization_code,
        )

        # CWE-384: Session Fixation
        # To prevent session fixation, a new session ID must be generated upon
        # successful authentication. This ensures that any pre-authentication
        # session ID (potentially controlled by an attacker) is invalidated
        # and cannot be used to hijack the authenticated session.

        # Store the current client-provided session ID for invalidation.
        current_browser_session_id = request.browser_session_id

        # Invalidate and remove the old session associated with the client-provided ID.
        # This prevents an attacker from reusing a fixed session ID.
        if current_browser_session_id in sessions:
            del sessions[current_browser_session_id]

        # Generate a new, cryptographically secure session ID.
        new_session_id = secrets.token_urlsafe(32)

        # Associate the authenticated identity with the newly generated session ID.
        # .setdefault ensures that `sessions[new_session_id]` is a dictionary
        # before attempting to set its "identity" key.
        sessions.setdefault(new_session_id, {})["identity"] = identity

        # Return the new session ID. The client is responsible for updating
        # its stored session ID (e.g., in a cookie) to this new value.
        return new_session_id
