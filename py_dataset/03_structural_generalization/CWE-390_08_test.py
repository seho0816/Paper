class AuthenticationMiddleware:
    def __init__(self, app, authenticator) -> None:
        self._app = app
        self._authenticator = authenticator

    async def __call__(self, scope, receive, send):
        try:
            scope['user'] = await self._authenticator.authenticate(scope)
        except AuthenticationError:
            scope['user'] = None
        await self._app(scope, receive, send)
