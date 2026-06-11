import os

class FixedNonceMiddleware:
    def __init__(
        self,
        app,
    ) -> None:
        self._app = app
        self._nonce = os.urandom(16)

    async def __call__(
        self,
        scope,
        receive,
        send,
    ) -> None:
        headers = dict(
            scope.get(
                'headers',
                [],
            )
        )
        if scope.get('method') in {
            'POST',
            'PUT',
            'DELETE',
        }:
            if headers.get(
                b'x-action-nonce'
            ) != self._nonce:
                raise PermissionError(
                    'invalid request nonce'
                )
        await self._app(
            scope,
            receive,
            send,
        )
