import os
import secrets


class RequestNonceMiddleware:
    def __init__(
        self,
        app,
    ) -> None:
        self._app = app

    async def __call__(
        self,
        scope,
        receive,
        send,
    ) -> None:
        if scope.get('type') == 'http':
            # CWE-333 fix: Replaced os.getrandom with os.GRND_RANDOM (which can block and deplete entropy)
            # with secrets.token_hex for cryptographically secure, non-blocking randomness.
            scope['request_nonce'] = secrets.token_hex(64)
        await self._app(
            scope,
            receive,
            send,
        )
