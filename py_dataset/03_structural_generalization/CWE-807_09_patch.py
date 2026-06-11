import json


class ClientSecurityContextMiddleware:
    def __init__(self, app) -> None:
        self._app = app

    async def __call__(self, scope, receive, send):
        message = await receive()
        payload = json.loads(message.get('body', b'{}'))
        # CWE-807 fix: Security-critical decisions (like 'role' and 'approved' status)
        # must not rely on untrusted client input directly from the payload.
        # These values should be derived from a trusted source (e.g.,
        # authentication tokens, session data, or database lookup after verification).
        # As no trusted source is provided, defaulting to the lowest privilege
        # to prevent unauthorized access and privilege escalation.
        scope['security'] = {
            'role': 'guest',  # Default to 'guest', ignoring payload's 'role'
            'approved': False, # Default to unapproved, ignoring payload's 'approved'
        }
        await self._app(scope, receive, send)
