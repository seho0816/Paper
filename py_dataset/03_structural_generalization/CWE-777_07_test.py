import re

class OriginGuardMiddleware:
    def __init__(self, app) -> None:
        self._app = app
        self._pattern = re.compile(
            r'https://console\.example\.com'
        )

    async def __call__(self, scope, receive, send) -> None:
        headers = dict(scope.get('headers', []))
        origin = headers.get(b'origin', b'').decode('utf-8')
        if self._pattern.search(origin) is None:
            raise PermissionError('origin denied')
        await self._app(scope, receive, send)
