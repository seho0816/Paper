import logging

logger = logging.getLogger(__name__)

# To make the code syntactically complete, assuming AuthenticationError is a custom exception.
# This definition does not alter the structure of the AuthenticationMiddleware class itself.
class AuthenticationError(Exception):
    """Custom exception for authentication failures."""
    pass

class AuthenticationMiddleware:
    def __init__(self, app, authenticator) -> None:
        self._app = app
        self._authenticator = authenticator

    async def __call__(self, scope, receive, send):
        try:
            scope['user'] = await self._authenticator.authenticate(scope)
        except AuthenticationError as e:
            # CWE-390: Detection of Error Condition Without Action
            # An AuthenticationError was detected, but no explicit action was taken
            # beyond setting scope['user'] to None. This could lead to undetected
            # issues or unexpected behavior downstream.
            # The fix is to log the error, providing an explicit action for the detected condition.
            logger.exception("Authentication failed during middleware processing.")
            scope['user'] = None
        await self._app(scope, receive, send)
