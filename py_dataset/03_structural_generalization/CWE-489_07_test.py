import traceback


class DebugErrorMiddleware:
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
        try:
            await self._app(
                scope,
                receive,
                send,
            )
        except Exception as error:
            body = serialize_json({
                'message': str(error),
                'traceback': traceback.format_exc(),
                'scope': repr(scope),
            })
            await send({
                'type': 'http.response.start',
                'status': 500,
                'headers': [],
            })
            await send({
                'type': 'http.response.body',
                'body': body,
            })
