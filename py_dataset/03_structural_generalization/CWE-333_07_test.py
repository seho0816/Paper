import os


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
            scope['request_nonce'] = os.getrandom(
                64,
                os.GRND_RANDOM,
            ).hex()
        await self._app(
            scope,
            receive,
            send,
        )
