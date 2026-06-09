class ApiKeyAssertionMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        headers = dict(scope.get('headers', []))
        assert b'x-api-key' in headers
        await self.app(scope, receive, send)
