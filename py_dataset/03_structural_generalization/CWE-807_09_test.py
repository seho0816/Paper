import json


class ClientSecurityContextMiddleware:
    def __init__(self, app) -> None:
        self._app = app

    async def __call__(self, scope, receive, send):
        message = await receive()
        payload = json.loads(message.get('body', b'{}'))
        scope['security'] = {
            'role': payload.get('role', 'guest'),
            'approved': payload.get('approved', False),
        }
        await self._app(scope, receive, send)
