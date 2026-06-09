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
        # CWE-777 (Polymorphic Typing) fix:
        # Using re.search allows partial matches, which could permit a malicious origin
        # like "evil.com/https://console.example.com" to bypass the check.
        # This is an interpretation of polymorphic typing where the string 'type'
        # intended for validation (exact match) is polymorphically interpreted
        # (allowing partial matches).
        # To strictly enforce that the entire origin string matches the pattern,
        # use re.fullmatch instead of re.search.
        if self._pattern.fullmatch(origin) is None:
            raise PermissionError('origin denied')
        await self._app(scope, receive, send)
